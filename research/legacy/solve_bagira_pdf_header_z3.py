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
import subprocess
import sys
import tempfile
from pathlib import Path

import z3

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"
FOLDER = r"archive-2026-09-03_14-15-10\extracted_correct"
SRC = SRC_ROOT / FOLDER


PDF_HEADERS = [
    b"%PDF-1.6\r%\xe2\xe3\xcf\xd3\r\n",
    b"%PDF-1.5\r%\xe2\xe3\xcf\xd3\r\n",
    b"%PDF-1.4\r%\xe2\xe3\xcf\xd3\r\n",
    b"%PDF-1.7\r%\xe2\xe3\xcf\xd3\r\n",
    b"%PDF-1.3\r%\xe2\xe3\xcf\xd3\r\n",
    b"%PDF-1.6\n%\xe2\xe3\xcf\xd3\n",
    b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n",
    b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n",
]


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    ks, _dumps, _learned, _conflicts, _label = rdt.build_name_ks_from_packer(files)
    if not ks:
        oracle = max(files, key=lambda item: item.coverage)
        base = rdt.run_dump_ks(oracle)
        if base:
            ks.update({i: b for i, b in enumerate(base)})
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    changed = True
    while changed:
        changed = False
        for item in sorted(files, key=lambda it: it.fei_len):
            if not rdt.output_path_for(item).exists():
                continue
            fek = rdt.derive_fek_from_ks(ks, item) or rdt.recover_fek_from_known_pair(item, ks)
            if not fek:
                continue
            learned = rdt.learn_fek(ks, item, fek)
            if learned:
                changed = True
    return ks


def solve_header(item: lr.EncryptedFile, ks: dict[int, int], timeout_ms: int) -> tuple[str, str, str]:
    enc = Path(item.path)
    fei_len, _fei_offset, _body_end, fei_ct, _kek = lr.read_fei_ciphertext(enc)
    fek_start = fei_len - 64
    missing = [off for off in range(fek_start, fei_len) if off not in ks]
    if not missing:
        fek = rdt.derive_fek_from_ks(ks, item)
        return ("sat", fek or "", "no_missing")
    if len(missing) > 10:
        return ("skip", "", f"missing_{len(missing)}")
    with enc.open("rb") as f:
        enc_head = f.read(64)
    if len(enc_head) < 16:
        return ("skip", "", "short_head")

    unknown_ks = {off: z3.BitVec(f"ks{off}", 8) for off in missing}
    fek_bytes = []
    for idx in range(64):
        off = fek_start + idx
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    words = salsa20_words_z3(state)

    for header in PDF_HEADERS:
        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        want = bytes(a ^ b for a, b in zip(enc_head[: len(header)], header))
        for wi in range((len(want) + 3) // 4):
            chunk = want[wi * 4 : wi * 4 + 4]
            if len(chunk) < 4:
                for bi, expected in enumerate(chunk):
                    solver.add(z3.Extract(8 * bi + 7, 8 * bi, words[wi]) == z3.BitVecVal(expected, 8))
            else:
                solver.add(words[wi] == z3.BitVecVal(int.from_bytes(chunk, "little"), 32))
        status = solver.check()
        if status != z3.sat:
            continue
        model = solver.model()
        local = dict(ks)
        for off in missing:
            local[off] = model.eval(unknown_ks[off]).as_long()
        fek = bytes(fei_ct[fek_start + i] ^ local[fek_start + i] for i in range(64))
        block = rdt.salsa20_block(fek)
        if bytes(a ^ b for a, b in zip(enc_head[: len(header)], block)) != header:
            continue
        return ("sat", fek.hex(), header.hex())
    return ("unsat", "", f"missing_{len(missing)}")


def try_decrypt(item: lr.EncryptedFile, fek_hex: str) -> bool:
    out = rdt.output_path_for(item)
    ext = rdt.infer_ext(item.original_name)
    if ext != "pdf":
        return False
    with tempfile.TemporaryDirectory(prefix="bagira_z3_") as td:
        tmp = Path(td) / _case_value('10e4dbcec46ccafd53be')
        before, after, skipped, _source = rdt.chunking_params_for(item, {})
        # BagIRA PDFs in this archive use the standard metadata profile.
        before, after, skipped = 3, 3, rdt.SKIPPED
        with rdt.helper_path(item.path, "z3") as hp:
            ok = rdt.direct_decrypt_with_timeout(
                rdt.REPO / "direct-decrypt.exe",
                hp,
                tmp,
                fek_hex,
                before,
                after,
                hex(skipped),
            )
        if ok and rdt.validate_recovered(tmp, ext):
            out.parent.mkdir(parents=True, exist_ok=True)
            tmp.replace(out)
            return True
    return False


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    max_missing = int(sys.argv[1]) if len(sys.argv) > 1 else 10
    timeout_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 120000
    groups, scanned, skipped = lr.scan_source(SRC, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    rows = []
    recovered = 0
    for kek, files in sorted(groups.items()):
        ks = build_group_ks(files)
        cov = rdt.contiguous(ks)
        for item in sorted(files, key=lambda it: (it.fei_len, it.original_name.lower())):
            if rdt.output_path_for(item).exists() or rdt.infer_ext(item.original_name) != "pdf":
                continue
            fei_len, _off, _body_end, _fei_ct, _kek = lr.read_fei_ciphertext(Path(item.path))
            missing = [off for off in range(fei_len - 64, fei_len) if off not in ks]
            if len(missing) > max_missing:
                continue
            status, fek_hex, detail = solve_header(item, ks, timeout_ms)
            wrote = False
            if status == "sat" and fek_hex:
                wrote = try_decrypt(item, fek_hex)
                if wrote:
                    recovered += 1
                    rdt.learn_fek(ks, item, fek_hex)
                    cov = rdt.contiguous(ks)
            rows.append(
                {
                    "status": status,
                    "wrote": str(wrote),
                    "kek": kek,
                    "coverage": str(cov),
                    "fei_len": str(item.fei_len),
                    "missing_count": str(len(missing)),
                    "detail": detail,
                    "encrypted_path": item.path,
                    "output_path": str(rdt.output_path_for(item)),
                }
            )
            print(
                f"{status} wrote={wrote} kek={kek} fei={item.fei_len} "
                f"missing={len(missing)} cov={cov} name={item.original_name}",
                flush=True,
            )
    report = REPORTS / "bagira_pdf_header_z3_attempts.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = [
            "status", "wrote", "kek", "coverage", "fei_len", "missing_count",
            "detail", "encrypted_path", "output_path",
        ]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"scanned={scanned} skipped={skipped} recovered={recovered} report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
