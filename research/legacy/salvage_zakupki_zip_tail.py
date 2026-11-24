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
import os
import shutil
import sys
import tempfile
import zlib
import zipfile
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from solve_zakupki_mp4_body_constraints_z3 import encrypted_windows, overlaps_windows


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
REPORT_ROOT = Path(_case_value('5d81163683a3688833d6'))
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def find_eocd(data: bytes) -> int:
    start = max(0, len(data) - (65535 + 22))
    return data.rfind(b"PK\x05\x06", start)


def parse_central_dir(data: bytes) -> list[dict[str, object]]:
    eocd = find_eocd(data)
    if eocd < 0 or eocd + 22 > len(data):
        return []
    total = int.from_bytes(data[eocd + 10:eocd + 12], "little")
    cd_size = int.from_bytes(data[eocd + 12:eocd + 16], "little")
    cd_off = int.from_bytes(data[eocd + 16:eocd + 20], "little")
    if cd_off + cd_size > len(data):
        return []
    pos = cd_off
    rows = []
    for _ in range(total):
        if pos + 46 > len(data) or data[pos:pos + 4] != b"PK\x01\x02":
            break
        method = int.from_bytes(data[pos + 10:pos + 12], "little")
        crc = int.from_bytes(data[pos + 16:pos + 20], "little")
        comp = int.from_bytes(data[pos + 20:pos + 24], "little")
        uncomp = int.from_bytes(data[pos + 24:pos + 28], "little")
        nlen = int.from_bytes(data[pos + 28:pos + 30], "little")
        xlen = int.from_bytes(data[pos + 30:pos + 32], "little")
        clen = int.from_bytes(data[pos + 32:pos + 34], "little")
        local_off = int.from_bytes(data[pos + 42:pos + 46], "little")
        name = data[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        rows.append(
            {
                "name": name,
                "method": method,
                "crc": crc,
                "comp": comp,
                "uncomp": uncomp,
                "local_off": local_off,
            }
        )
        pos += 46 + nlen + xlen + clen
    return rows


def extract_entry(data: bytes, row: dict[str, object], wins: list[tuple[int, int]]) -> bytes | None:
    local = int(row["local_off"])
    if local + 30 > len(data) or data[local:local + 4] != b"PK\x03\x04":
        return None
    nlen = int.from_bytes(data[local + 26:local + 28], "little")
    xlen = int.from_bytes(data[local + 28:local + 30], "little")
    start = local + 30 + nlen + xlen
    end = start + int(row["comp"])
    if end > len(data):
        return None
    if overlaps_windows(local, end, wins):
        return None
    blob = data[start:end]
    method = int(row["method"])
    try:
        if method == 0:
            out = blob
        elif method == 8:
            out = zlib.decompress(blob, -15)
        else:
            return None
    except zlib.error:
        return None
    if len(out) != int(row["uncomp"]):
        return None
    return out


def generic_content_types(names: set[str], ext: str) -> bytes:
    defaults = {
        "rels": "application/vnd.openxmlformats-package.relationships+xml",
        "xml": "application/xml",
        "jpeg": "image/jpeg",
        "jpg": "image/jpeg",
        "png": "image/png",
        "emf": "image/x-emf",
        "wmf": "image/x-wmf",
    }
    overrides = []
    if ext == "docx":
        overrides.append(("/word/document.xml", "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"))
    if ext == "xlsx":
        overrides.append(("/xl/workbook.xml", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"))
    parts = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
             _case_value('69691ff6d05cd7f90384')]
    for suffix, ctype in defaults.items():
        parts.append(f'<Default Extension="{suffix}" ContentType="{ctype}"/>')
    for part, ctype in overrides:
        if part.lstrip("/") in names:
            parts.append(f'<Override PartName="{part}" ContentType="{ctype}"/>')
    parts.append("</Types>")
    return "".join(parts).encode("utf-8")


def salvage_item(item: lr.EncryptedFile, ks: dict[int, int]) -> dict[str, object]:
    enc = Path(item.path)
    rel = out_rel_for(enc)
    ext = rel.suffix.lower().lstrip(".")
    fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
    data = enc.read_bytes()[:body_end]
    before, after, skipped, source = rdt.chunking_params_for(item, ks)
    wins = encrypted_windows(body_end, before, after, skipped)
    rows = parse_central_dir(data)
    extracted: dict[str, bytes] = {}
    for row in rows:
        name = str(row["name"])
        payload = extract_entry(data, row, wins)
        if payload is not None:
            extracted[name] = payload
    if "[Content_Types].xml" not in extracted:
        extracted["[Content_Types].xml"] = generic_content_types(set(extracted), ext)

    safe = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in str(rel))[:180]
    preview = REPORT_ROOT / f"{safe}.salvaged.{ext}"
    preview.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(preview, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, payload in sorted(extracted.items()):
            zf.writestr(name, payload)
    real_entries = set(extracted) - {"[Content_Types].xml"}
    has_required_payload = (
        ext == "docx" and any(name.startswith("word/") for name in real_entries)
    ) or (
        ext == "xlsx" and any(name.startswith("xl/") for name in real_entries)
    )
    valid = bool(rows) and bool(real_entries) and has_required_payload and rdt.validate_recovered(preview, ext)
    status = "VALID_SALVAGE" if valid else "PARTIAL_SALVAGE"
    if valid:
        out = OUT_ROOT / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(preview, out)
    return {
        "rel": str(rel),
        "ext": ext,
        "status": status,
        "fei_len": fei_len,
        "body_end": body_end,
        "params": f"{before}/{after}/0x{skipped:x}/{source}",
        "central_entries": len(rows),
        "extracted_entries": len(extracted),
        "real_entries": len(real_entries),
        "has_required_payload": has_required_payload,
        "preview": str(preview),
    }


def main() -> int:
    REPORT_ROOT.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    results = []
    for kek, files in groups.items():
        ks = build_group_keystream(files)
        for item in files:
            rel = out_rel_for(Path(item.path))
            if rel.suffix.lower().lstrip(".") not in {"docx", "xlsx"}:
                continue
            if (OUT_ROOT / rel).exists():
                continue
            try:
                row = salvage_item(item, ks)
            except Exception as exc:
                row = {"rel": str(rel), "status": "ERROR_" + type(exc).__name__, "detail": str(exc)}
            row["kek"] = kek
            results.append(row)
            print(row, flush=True)
    report = REPORT_ROOT / "summary.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = sorted({k for row in results for k in row}) if results else ["rel"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(results)
    print(f"report={report}")
    print(f"valid={sum(1 for r in results if r.get('status') == 'VALID_SALVAGE')} partial={sum(1 for r in results if r.get('status') == 'PARTIAL_SALVAGE')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
