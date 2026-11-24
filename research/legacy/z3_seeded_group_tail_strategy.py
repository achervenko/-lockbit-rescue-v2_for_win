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
import json
import os
import sys
from pathlib import Path

import z3


def add_import_paths(repo_root: Path, work_root: Path) -> None:
    for path in [str(repo_root), str(work_root)]:
        if path not in sys.path:
            sys.path.insert(0, path)


def strategy_list(max_strategies: int, width: int) -> list[tuple[int, ...]]:
    priority = [
        (0,), (1,), (2,), (3,), (14,), (15,), (7,), (8,),
        (0, 1), (14, 15), (0, 15), (7, 8), (3, 12), (5, 10),
        (1, 14), (2, 15), (4, 13), (6, 11), (8, 15), (0, 7),
        (0, 1, 2), (13, 14, 15), (0, 14, 15), (6, 7, 8),
    ]
    combos: list[tuple[int, ...]] = []
    for w in range(1, width + 1):
        combos.extend(itertools.combinations(range(16), w))
    out: list[tuple[int, ...]] = []
    for s in priority + combos:
        if len(s) <= width and s not in out:
            out.append(s)
        if len(out) >= max_strategies:
            break
    return out


def load_seed(seed_path: Path, kek: str) -> dict[int, int]:
    data = json.loads(seed_path.read_text(encoding="utf-8"))
    group = data.get("groups", {}).get(kek)
    if not group:
        raise RuntimeError(f"KEK {kek} not found in seed {seed_path}")
    return {int(off): int(hex_byte, 16) for off, hex_byte in group["ks"].items()}


def ranges(offsets: list[int]) -> str:
    if not offsets:
        return ""
    offsets = sorted(offsets)
    out = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = off
    out.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(out)


def solve_strategy(rdt, word_from_bytes, salsa20_words_z3, kek: str, ks: dict[int, int], pairs, words: tuple[int, ...], timeout_ms: int) -> dict[str, str]:
    cov = rdt.contiguous(ks)
    max_off = max(max(row["missing"]) for row in pairs)
    unknown_ks = {off: z3.BitVec(f"ks{off}", 8) for off in range(cov, max_off + 1) if off not in ks}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    for row in pairs:
        fei_len = row["fei_len"]
        fei_ct = row["fei_ct"]
        expected = row["expected"]
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
    result = {
        "status": str(status),
        "kek": kek,
        "coverage": str(cov),
        "max_off": str(max_off),
        "unknown_bytes": str(len(unknown_ks)),
        "pairs": str(len(pairs)),
        "words": ",".join(map(str, words)),
        "ks_offsets": ranges(sorted(unknown_ks)),
        "ks_hex": "",
        "full_verify": "",
    }
    if status != z3.sat:
        return result

    model = solver.model()
    vals = {off: model.eval(var, model_completion=True).as_long() for off, var in unknown_ks.items()}
    result["ks_hex"] = "".join(f"{vals[off]:02x}" for off in sorted(vals))
    ok = True
    for row in pairs:
        fei_len = row["fei_len"]
        fei_ct = row["fei_ct"]
        expected = row["expected"]
        start = fei_len - 64
        fek = bytearray(64)
        for i in range(64):
            off = start + i
            ksb = ks[off] if off in ks else vals[off]
            fek[i] = fei_ct[off] ^ ksb
        if rdt.salsa20_block(bytes(fek)) != expected:
            ok = False
            break
    result["full_verify"] = str(ok)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kek", required=True)
    parser.add_argument("--src-root", type=Path, required=True, help="Path to encrypted root, e.g. ...\\Зашифрованные файлы")
    parser.add_argument("--dst-root", type=Path, required=True, help="Path to recovered root, e.g. ...\\Восстановленные файлы")
    parser.add_argument("--repo-root", type=Path, default=Path(_project_path('')))
    parser.add_argument("--work-root", type=Path, default=Path.cwd())
    parser.add_argument("--seed-json", type=Path, default=Path("sklad_z3_keystream_seed.json"))
    parser.add_argument("--max-missing", type=int, default=12)
    parser.add_argument("--pairs", type=int, default=4)
    parser.add_argument("--strategy-width", type=int, default=2)
    parser.add_argument("--max-strategies", type=int, default=32)
    parser.add_argument("--timeout-ms", type=int, default=120_000)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    os.environ["PATH"] = str(args.repo_root) + os.pathsep + os.environ.get("PATH", "")
    add_import_paths(args.repo_root, args.work_root)

    import lockbit_rescue_v2 as lr
    import recover_desktop_tree as rdt
    from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes

    # Patch module globals so helper functions use this PC's extracted paths.
    rdt.SRC_ROOT = args.src_root
    rdt.SRC = args.src_root / "СКЛАД"
    rdt.DST = args.dst_root
    rdt.REPORTS = args.dst_root / "_technical_reports"
    rdt.REPO = args.repo_root

    ks = load_seed(args.seed_json, args.kek)
    print(f"seed coverage={rdt.contiguous(ks)} known={len(ks)} seed={args.seed_json}")

    groups, _, _ = lr.scan_source(args.src_root / "СКЛАД", [rdt.EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups.get(args.kek)
    if not files:
        raise RuntimeError(f"KEK not found in encrypted files: {args.kek}")

    rows = []
    cov = rdt.contiguous(ks)
    for item in files:
        enc = Path(item.path)
        rel = enc.relative_to(args.src_root)
        out = args.dst_root / Path(str(rel)[: -len(rdt.EXT)])
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
        if not missing or len(missing) > args.max_missing or min(missing) != cov:
            continue
        with enc.open("rb") as ef, out.open("rb") as pf:
            expected = bytes(a ^ b for a, b in zip(ef.read(64), pf.read(64)))
        if len(expected) != 64:
            continue
        rows.append(
            {
                "missing_count": len(missing),
                "fei_len": fei_len,
                "name": item.original_name.lower(),
                "item": item,
                "fei_ct": fei_ct,
                "expected": expected,
                "missing": missing,
            }
        )
    rows.sort(key=lambda r: (r["missing_count"], r["fei_len"], r["name"]))
    pairs = rows[: args.pairs]
    print(f"kek={args.kek} coverage={cov} exact_pairs={len(pairs)}")
    for row in pairs:
        print(f" pair missing={row['missing_count']} fei={row['fei_len']} offsets={ranges(row['missing'])} name={row['item'].original_name}")
    if not pairs:
        return 2

    report = args.out or (args.dst_root / "_technical_reports" / f"z3_seeded_group_tail_{args.kek}.csv")
    report.parent.mkdir(parents=True, exist_ok=True)
    exists = report.exists()
    fields = ["status", "kek", "coverage", "max_off", "unknown_bytes", "pairs", "words", "ks_offsets", "ks_hex", "full_verify"]
    with report.open("a", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        for idx, words in enumerate(strategy_list(args.max_strategies, args.strategy_width), 1):
            row = solve_strategy(rdt, word_from_bytes, salsa20_words_z3, args.kek, ks, pairs, words, args.timeout_ms)
            writer.writerow({field: row.get(field, "") for field in fields})
            fh.flush()
            print(f"{idx}/{args.max_strategies} words={words} status={row['status']} unknown={row['unknown_bytes']} full={row.get('full_verify','')}")
            if row.get("full_verify") == "True":
                print(f"FOUND offsets={row['ks_offsets']} ks_hex={row['ks_hex']}")
                print(f"report={report}")
                return 0
    print(f"report={report}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
