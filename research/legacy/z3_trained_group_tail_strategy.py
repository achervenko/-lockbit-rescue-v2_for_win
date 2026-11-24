from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import argparse
import csv
import itertools
import sys
from pathlib import Path

import z3

sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    base = rdt.run_dump_ks(max(files, key=lambda f: f.coverage))
    if not base:
        return {}
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def exact_pairs(files: list[lr.EncryptedFile], ks: dict[int, int], max_missing: int, pair_limit: int):
    cov = rdt.contiguous(ks)
    rows = []
    for item in files:
        enc = Path(item.path)
        out = output_path_for(item)
        if not out.exists() or not out.is_file():
            continue
        try:
            fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
        except Exception:
            continue
        if out.stat().st_size != body_end:
            continue
        start = fei_len - 64
        missing = [off for off in range(start, fei_len) if off not in ks]
        if not missing or len(missing) > max_missing or min(missing) != cov:
            continue
        with enc.open("rb") as ef, out.open("rb") as pf:
            expected = bytes(a ^ b for a, b in zip(ef.read(64), pf.read(64)))
        if len(expected) != 64:
            continue
        rows.append((len(missing), fei_len, item.original_name.lower(), item, fei_ct, expected, missing))
    rows.sort()
    return rows[:pair_limit]


def strategy_list(max_strategies: int, width: int) -> list[tuple[int, ...]]:
    priority = [
        (0,), (1,), (2,), (3,), (14,), (15,), (7,), (8,),
        (0, 1), (14, 15), (0, 15), (7, 8), (3, 12), (5, 10),
        (1, 14), (2, 15), (4, 13), (6, 11), (8, 15), (0, 7),
    ]
    all_s = []
    for w in range(1, width + 1):
        all_s.extend(itertools.combinations(range(16), w))
    out = []
    for s in priority + all_s:
        if len(s) <= width and s not in out:
            out.append(s)
        if len(out) >= max_strategies:
            break
    return out


def solve_strategy(kek: str, ks: dict[int, int], pairs, words: tuple[int, ...], timeout_ms: int) -> dict[str, str]:
    cov = rdt.contiguous(ks)
    max_off = max(max(row[6]) for row in pairs)
    unknown_ks = {off: z3.BitVec(f"ks{off}", 8) for off in range(cov, max_off + 1)}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for _, fei_len, _, item, fei_ct, expected, _ in pairs:
        start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
        state = [word_from_bytes(fek_bytes[i * 4:i * 4 + 4]) for i in range(16)]
        out_words = salsa20_words_z3(state)
        for wi in words:
            solver.add(out_words[wi] == z3.BitVecVal(int.from_bytes(expected[wi * 4:wi * 4 + 4], "little"), 32))
    status = solver.check()
    row = {
        "status": str(status),
        "kek": kek,
        "coverage": str(cov),
        "max_off": str(max_off),
        "unknown_bytes": str(max_off - cov + 1),
        "pairs": str(len(pairs)),
        "words": ",".join(map(str, words)),
        "ks_hex": "",
        "full_verify": "",
    }
    if status != z3.sat:
        return row
    model = solver.model()
    vals = bytes(model.eval(unknown_ks[off], model_completion=True).as_long() for off in range(cov, max_off + 1))
    row["ks_hex"] = vals.hex()
    ok = True
    for _, fei_len, _, item, fei_ct, expected, _ in pairs:
        start = fei_len - 64
        fek = bytearray(64)
        for i in range(64):
            off = start + i
            ksb = ks[off] if off in ks else vals[off - cov]
            fek[i] = fei_ct[off] ^ ksb
        if rdt.salsa20_block(bytes(fek)) != expected:
            ok = False
            break
    row["full_verify"] = str(ok)
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kek", required=True)
    parser.add_argument("--max-missing", type=int, default=12)
    parser.add_argument("--pairs", type=int, default=4)
    parser.add_argument("--strategy-width", type=int, default=2)
    parser.add_argument("--max-strategies", type=int, default=24)
    parser.add_argument("--timeout-ms", type=int, default=120_000)
    args = parser.parse_args()

    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups.get(args.kek)
    if not files:
        raise RuntimeError(f"KEK not found: {args.kek}")
    ks = build_group_ks(files)
    pairs = exact_pairs(files, ks, args.max_missing, args.pairs)
    print(f"kek={args.kek} coverage={rdt.contiguous(ks)} exact_pairs={len(pairs)}")
    for row in pairs:
        print(f" pair missing={len(row[6])} fei={row[1]} name={row[3].original_name}")
    if not pairs:
        return 2

    report = REPORTS / f"z3_trained_group_tail_{args.kek}.csv"
    exists = report.exists()
    fields = ["status", "kek", "coverage", "max_off", "unknown_bytes", "pairs", "words", "ks_hex", "full_verify"]
    with report.open("a", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        for idx, words in enumerate(strategy_list(args.max_strategies, args.strategy_width), 1):
            row = solve_strategy(args.kek, ks, pairs, words, args.timeout_ms)
            writer.writerow({field: row.get(field, "") for field in fields})
            fh.flush()
            print(f"{idx}/{args.max_strategies} words={words} status={row['status']} full={row.get('full_verify','')}")
            if row.get("full_verify") == "True":
                print(f"FOUND ks_hex={row['ks_hex']}")
                print(f"report={report}")
                return 0
    print(f"report={report}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
