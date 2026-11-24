from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import csv
import shutil
import sys
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from salvage_ohrana_gap0 import (
    DST_ROOT,
    EXT,
    FOLDER,
    REPORTS,
    SALVAGE_ROOT,
    SRC_ROOT,
    build_group_ks,
    enc_path_for_rel,
    out_path_for,
    pdf_soft_check,
)


CHUNK_SIZE = 0x20000


def state_from_key(fek: bytes) -> list[int]:
    return [int.from_bytes(fek[i * 4 : i * 4 + 4], "little") for i in range(16)]


def salsa_stream_xor(buf: bytearray, state: list[int], offset: int, size: int) -> None:
    pos = 0
    while pos < size:
        block = rdt.salsa20_block(b"".join(w.to_bytes(4, "little") for w in state))
        n = min(64, size - pos)
        for i in range(n):
            buf[offset + pos + i] ^= block[i]
        state[8] = (state[8] + 1) & 0xFFFFFFFF
        if state[8] == 0:
            state[9] = (state[9] + 1) & 0xFFFFFFFF
        pos += n


def tail_aware_decrypt(enc: Path, fek_hex: str, first_chunks: int, tail_chunks: int) -> bytes:
    fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
    data = bytearray(enc.read_bytes()[:body_end])
    state = state_from_key(bytes.fromhex(fek_hex))

    first_end = min(body_end, first_chunks * CHUNK_SIZE)
    if first_end:
        salsa_stream_xor(data, state, 0, first_end)

    tail_start = max(first_end, body_end - tail_chunks * CHUNK_SIZE)
    tail_size = body_end - tail_start
    if tail_size > 0:
        salsa_stream_xor(data, state, tail_start, tail_size)
    return bytes(data)


def html_soft_check(path: Path) -> tuple[bool, str]:
    data = path.read_bytes()
    if data.startswith(b"\xff\xfe"):
        text = data.decode("utf-16le", errors="ignore").lower()
        if "<html" in text or "<!doctype html" in text:
            return True, "html_utf16le"
    text = data.decode("utf-8", errors="ignore").lower()
    if "<html" in text or "<!doctype html" in text:
        return True, "html_utf8"
    return False, "no_html_marker"


def main() -> int:
    SALVAGE_ROOT.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(
        SRC_ROOT / FOLDER, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    item_by_path = {Path(item.path): (kek, files, item) for kek, files in groups.items() for item in files}
    ks_by_kek = {kek: build_group_ks(kek, files) for kek, files in groups.items()}

    rows = []
    recovered = 0
    analysis = REPORTS / "ohrana_remaining_35_analysis.csv"
    with analysis.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["recoverability"] != "DIRECT_POSSIBLE" or row["is_temp_office"] != "0":
                continue
            if row["ext"] not in {"pdf", "htm", "html"}:
                continue
            enc = enc_path_for_rel(row["rel_path"])
            out = out_path_for(enc)
            if enc not in item_by_path:
                continue
            kek, files, item = item_by_path[enc]
            ks = ks_by_kek[kek]
            fek_hex = rdt.derive_fek_from_ks(ks, item)
            if not fek_hex:
                continue

            best_status = "NO_VARIANT"
            best_detail = ""
            best_path = ""
            if row["ext"] in {"htm", "html"}:
                # Existing direct decrypt output is already enough; validate UTF-16LE.
                tmp = SALVAGE_ROOT / Path(row["rel_path"]).name
                if tmp.exists():
                    ok, detail = html_soft_check(tmp)
                    if ok:
                        out.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(tmp, out)
                        best_status = "RECOVERED_HTML"
                        best_detail = detail
                        best_path = str(tmp)
                        recovered += 1
                row.update({"status": best_status, "detail": best_detail, "salvage_path": best_path})
                rows.append(row)
                continue

            for first_chunks in (3, 4):
                for tail_chunks in (3, 4):
                    data = tail_aware_decrypt(enc, fek_hex, first_chunks, tail_chunks)
                    if b"%%EOF" not in data or b"startxref" not in data:
                        if best_status == "NO_VARIANT":
                            best_detail = "no_eof_startxref"
                        continue
                    tmp = SALVAGE_ROOT / f"tail_{first_chunks}_{tail_chunks}_{Path(row['rel_path']).name}"
                    tmp.write_bytes(data)
                    ok, detail = pdf_soft_check(tmp)
                    if ok:
                        out.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(tmp, out)
                        best_status = "RECOVERED_TAIL_AWARE"
                        best_detail = f"{detail};first={first_chunks};tail={tail_chunks};size={len(data)}"
                        best_path = str(tmp)
                        recovered += 1
                        break
                    if best_status == "NO_VARIANT":
                        best_detail = detail
                        best_path = str(tmp)
                if best_status == "RECOVERED_TAIL_AWARE":
                    break
            row.update({"status": best_status, "detail": best_detail, "salvage_path": best_path})
            rows.append(row)

    report = REPORTS / "ohrana_tail_chunk_salvage_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = list(rows[0].keys()) if rows else ["status"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"recovered={recovered}")
    print(f"report={report}")
    for row in rows:
        print(f"{row['status']} {row.get('detail','')} :: {row['rel_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
