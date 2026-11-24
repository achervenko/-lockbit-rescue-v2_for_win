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
import sys
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
KEK = _case_value('334d517b17c31441017e')

PAIR_ROOTS = [
    Path(_case_value('793313ad8753ea27fb46')),
    Path(_case_value('4ad553a2014833d3f789')),
    Path(_case_value('f4e5e33bf20cc2d98993')),
]


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump base ks")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def find_plain(item: lr.EncryptedFile, body_end: int) -> Path | None:
    out = DST_ROOT / Path(str(Path(item.path).relative_to(SRC_ROOT))[: -len(EXT)])
    candidates = [out]
    name = item.original_name
    for root in PAIR_ROOTS:
        if not root.exists():
            continue
        candidates.extend(root.rglob(name))
    seen = set()
    for cand in candidates:
        if cand in seen or not cand.is_file():
            continue
        seen.add(cand)
        try:
            if cand.stat().st_size == body_end:
                return cand
        except OSError:
            continue
    return None


def first64_xor(enc: Path, plain: Path) -> bytes | None:
    with enc.open("rb") as ef, plain.open("rb") as pf:
        a = ef.read(64)
        b = pf.read(64)
    if len(a) != 64 or len(b) != 64:
        return None
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> int:
    max_pairs = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    words_limit = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    timeout_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 300_000
    max_unknown = int(sys.argv[4]) if len(sys.argv) > 4 else 9

    groups, scanned, skipped = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    files = groups.get(KEK, [])
    if not files:
        raise RuntimeError(f"group {KEK} not found")

    ks = build_group_ks(files)
    base_cov = rdt.contiguous(ks)
    candidates = []
    for item in files:
        enc = Path(item.path)
        try:
            fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
        except Exception:
            continue
        missing = [off for off in range(fei_len - 64, fei_len) if off not in ks]
        if not missing or min(missing) != base_cov:
            continue
        if max(missing) - base_cov + 1 > max_unknown:
            continue
        plain = find_plain(item, body_end)
        if plain is None:
            continue
        expected = first64_xor(enc, plain)
        if expected is None:
            continue
        candidates.append((len(missing), fei_len, item.original_name.lower(), item, fei_ct, expected, missing, plain))

    candidates.sort()
    selected = candidates[:max_pairs]
    if not selected:
        print({"status": "no_candidate_pairs", "base_cov": base_cov, "scanned": scanned, "skipped": skipped})
        return 2

    max_off = max(max(row[6]) for row in selected)
    unknown_ks = {off: z3.BitVec(f"ks{off}", 8) for off in range(base_cov, max_off + 1)}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    for _, fei_len, _, item, fei_ct, expected, _, _ in selected:
        fek_start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = fek_start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
        state = [word_from_bytes(fek_bytes[i * 4:i * 4 + 4]) for i in range(16)]
        out_words = salsa20_words_z3(state)
        for wi in range(words_limit):
            expected_word = int.from_bytes(expected[wi * 4:wi * 4 + 4], "little")
            solver.add(out_words[wi] == z3.BitVecVal(expected_word, 32))

    status = solver.check()
    row = {
        "status": str(status),
        "kek": KEK,
        "base_cov": str(base_cov),
        "max_off": str(max_off),
        "unknown_count": str(max_off - base_cov + 1),
        "pairs": str(len(selected)),
        "words_limit": str(words_limit),
        "timeout_ms": str(timeout_ms),
        "ks_hex": "",
        "verified_all_first64": "",
    }
    if status == z3.sat:
        model = solver.model()
        vals = bytes(model.eval(unknown_ks[off]).as_long() for off in range(base_cov, max_off + 1))
        row["ks_hex"] = vals.hex()
        # Verify against the full first Salsa block for every selected pair.
        ok = True
        for _, fei_len, _, _, fei_ct, expected, _, _ in selected:
            fek_start = fei_len - 64
            fek = bytearray(64)
            for i in range(64):
                off = fek_start + i
                ksb = ks[off] if off in ks else vals[off - base_cov]
                fek[i] = fei_ct[off] ^ ksb
            if rdt.salsa20_block(bytes(fek)) != expected:
                ok = False
                break
        row["verified_all_first64"] = str(ok)
        if ok:
            for i, b in enumerate(vals):
                ks[base_cov + i] = b
            row["new_cov"] = str(rdt.contiguous(ks))
        else:
            row["new_cov"] = str(base_cov)
    else:
        row["new_cov"] = str(base_cov)

    REPORTS.mkdir(parents=True, exist_ok=True)
    report = REPORTS / "sklad_4f_external_pairs_z3.csv"
    exists = report.exists()
    fields = [
        "status", "kek", "base_cov", "max_off", "unknown_count", "pairs",
        "words_limit", "timeout_ms", "ks_hex", "verified_all_first64", "new_cov",
    ]
    with report.open("a", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})

    detail = REPORTS / "sklad_4f_external_pairs_z3_pairs.csv"
    with detail.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["fei_len", "missing", "original_name", "encrypted", "plain"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for _, fei_len, _, item, _, _, missing, plain in selected:
            writer.writerow({
                "fei_len": fei_len,
                "missing": ",".join(map(str, missing)),
                "original_name": item.original_name,
                "encrypted": item.path,
                "plain": str(plain),
            })

    print(row)
    print(f"report={report}")
    print(f"pairs={detail}")
    return 0 if row.get("verified_all_first64") == "True" else 2


if __name__ == "__main__":
    raise SystemExit(main())
