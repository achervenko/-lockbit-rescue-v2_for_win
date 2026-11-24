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
import os
import sys
from collections import Counter
from pathlib import Path

import z3

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"
KEK = _case_value('4906e8c091d91acf1ae1')


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def ranges(offsets: list[int]) -> str:
    if not offsets:
        return ""
    out: list[str] = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = off
    out.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(out)


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump base keystream")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def exact_pdf_samples(files: list[lr.EncryptedFile]) -> list[bytes]:
    samples: list[bytes] = []
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        out = output_path_for(item)
        if not out.exists() or not out.is_file():
            continue
        try:
            _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        if out.stat().st_size != body_end:
            continue
        data = out.read_bytes()
        if data.startswith(b"%PDF-"):
            samples.append(data)
    return samples


def common_prefix(samples: list[bytes], prefix_len: int) -> tuple[bytes, int, float]:
    counter = Counter(data[:prefix_len] for data in samples if len(data) >= prefix_len)
    if not counter:
        return b"", 0, 0.0
    blob, count = counter.most_common(1)[0]
    return blob, count, count / len(samples)


def collect_pseudo_pairs(
    files: list[lr.EncryptedFile],
    ks: dict[int, int],
    prefix: bytes,
    max_gap: int,
    limit: int,
) -> list[dict[str, object]]:
    cov = rdt.contiguous(ks)
    rows: list[tuple[int, int, int, str, dict[str, object]]] = []
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        if output_path_for(item).exists():
            continue
        try:
            fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        start = fei_len - 64
        missing = [off for off in range(start, fei_len) if off not in ks]
        if not missing or min(missing) != cov or len(missing) > max_gap:
            continue
        blocks = len(prefix) // 64
        with Path(item.path).open("rb") as fh:
            enc0 = fh.read(blocks * 64)
        if len(enc0) != blocks * 64 or blocks < 1:
            continue
        expected_blocks = {
            block_index: bytes(
                a ^ b
                for a, b in zip(
                    enc0[block_index * 64 : block_index * 64 + 64],
                    prefix[block_index * 64 : block_index * 64 + 64],
                )
            )
            for block_index in range(blocks)
        }
        rel = str(Path(item.path).relative_to(SRC_ROOT))[: -len(EXT)]
        rows.append(
            (
                len(missing),
                fei_len,
                -body_end,
                rel,
                {
                    "name": item.original_name,
                    "rel": rel,
                    "fei_len": fei_len,
                    "body_end": body_end,
                    "fei_ct": fei_ct,
                    "expected_blocks": expected_blocks,
                    "missing": missing,
                },
            )
        )
    rows.sort()
    return [row[-1] for row in rows[:limit]]


def collect_exact_pairs(
    files: list[lr.EncryptedFile],
    ks: dict[int, int],
    max_gap: int,
    limit: int,
) -> list[dict[str, object]]:
    cov = rdt.contiguous(ks)
    rows: list[tuple[int, int, int, str, dict[str, object]]] = []
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        out = output_path_for(item)
        if not out.exists() or not out.is_file():
            continue
        try:
            fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        if out.stat().st_size != body_end:
            continue
        start = fei_len - 64
        missing = [off for off in range(start, fei_len) if off not in ks]
        if not missing or min(missing) != cov or len(missing) > max_gap:
            continue
        with Path(item.path).open("rb") as ef, out.open("rb") as pf:
            enc0 = ef.read(128)
            plain0 = pf.read(128)
        if len(enc0) < 64 or len(plain0) < 64 or not plain0.startswith(b"%PDF-"):
            continue
        blocks = min(len(enc0), len(plain0)) // 64
        expected_blocks = {
            block_index: bytes(
                a ^ b
                for a, b in zip(
                    enc0[block_index * 64 : block_index * 64 + 64],
                    plain0[block_index * 64 : block_index * 64 + 64],
                )
            )
            for block_index in range(blocks)
        }
        rel = str(Path(item.path).relative_to(SRC_ROOT))[: -len(EXT)]
        rows.append(
            (
                len(missing),
                fei_len,
                -body_end,
                rel,
                {
                    "kind": "exact",
                    "name": item.original_name,
                    "rel": rel,
                    "fei_len": fei_len,
                    "body_end": body_end,
                    "fei_ct": fei_ct,
                    "expected_blocks": expected_blocks,
                    "missing": missing,
                },
            )
        )
    rows.sort()
    return [row[-1] for row in rows[:limit]]


def add_pair_constraints(
    solver: z3.Solver,
    pair: dict[str, object],
    ks: dict[int, int],
    unknown: dict[int, z3.BitVecRef],
    words: tuple[int, ...],
) -> None:
    fei_len = int(pair["fei_len"])
    fei_ct: bytes = pair["fei_ct"]  # type: ignore[assignment]
    expected_blocks: dict[int, bytes] = pair["expected_blocks"]  # type: ignore[assignment]
    start = fei_len - 64
    fek_bytes = []
    for i in range(64):
        off = start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])
    base_state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    for block_index, expected in sorted(expected_blocks.items()):
        state = base_state[:]
        state[8] = state[8] + z3.BitVecVal(block_index, 32)
        out_words = salsa20_words_z3(state)
        for wi in words:
            solver.add(out_words[wi] == z3.BitVecVal(int.from_bytes(expected[wi * 4 : wi * 4 + 4], "little"), 32))


def solve_strategy(
    ks: dict[int, int],
    pairs: list[dict[str, object]],
    words: tuple[int, ...],
    timeout_ms: int,
) -> dict[str, str]:
    all_missing = sorted({off for pair in pairs for off in pair["missing"]})  # type: ignore[index]
    unknown = {off: z3.BitVec(f"ks{off}", 8) for off in all_missing if off not in ks}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for pair in pairs:
        add_pair_constraints(solver, pair, ks, unknown, words)
    status = solver.check()
    row = {
        "status": str(status),
        "words": ",".join(map(str, words)),
        "pseudo_pairs": str(len(pairs)),
        "unknown_bytes": str(len(unknown)),
        "ks_offsets": ranges(sorted(unknown)),
        "ks_hex": "",
        "full_verify": "",
    }
    if status != z3.sat:
        return row
    model = solver.model()
    vals = {off: model.eval(var, model_completion=True).as_long() for off, var in unknown.items()}
    row["ks_hex"] = "".join(f"{vals[off]:02x}" for off in sorted(vals))
    ok = True
    for pair in pairs:
        fei_len = int(pair["fei_len"])
        fei_ct: bytes = pair["fei_ct"]  # type: ignore[assignment]
        expected_blocks: dict[int, bytes] = pair["expected_blocks"]  # type: ignore[assignment]
        start = fei_len - 64
        fek = bytearray(64)
        for i in range(64):
            off = start + i
            ksb = ks[off] if off in ks else vals[off]
            fek[i] = fei_ct[off] ^ ksb
        for block_index, expected in sorted(expected_blocks.items()):
            state = [int.from_bytes(fek[i * 4 : i * 4 + 4], "little") for i in range(16)]
            state[8] = (state[8] + block_index) & 0xFFFFFFFF
            got = rdt.salsa20_block(b"".join(v.to_bytes(4, "little") for v in state))
            if got != expected:
                ok = False
                break
        if not ok:
            break
    row["full_verify"] = str(ok)
    return row


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix-len", type=int, default=128)
    parser.add_argument("--max-gap", type=int, default=12)
    parser.add_argument("--exact-pairs", type=int, default=4)
    parser.add_argument("--pairs", type=int, default=4)
    parser.add_argument("--max-strategies", type=int, default=12)
    parser.add_argument("--timeout-ms", type=int, default=120_000)
    parser.add_argument("--out", type=Path, default=REPORTS / "pdf_profile_pseudopair_624.csv")
    args = parser.parse_args()

    groups, scanned, skipped = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups.get(KEK, [])
    if not files:
        raise RuntimeError(f"KEK group not found: {KEK}")
    print(f"scanned={scanned} skipped={skipped} kek={KEK} files={len(files)}", flush=True)
    print("building current FEI keystream...", flush=True)
    ks = build_group_ks(files)
    cov = rdt.contiguous(ks)
    print(f"current coverage={cov} known_ks={len(ks)}", flush=True)
    print("building recovered-PDF profile...", flush=True)
    samples = exact_pdf_samples(files)
    prefix, prefix_count, prefix_frac = common_prefix(samples, args.prefix_len)
    if not prefix:
        raise RuntimeError("no common PDF prefix")
    exact_pairs = collect_exact_pairs(files, ks, args.max_gap, args.exact_pairs)
    pseudo_pairs = collect_pseudo_pairs(files, ks, prefix, args.max_gap, args.pairs)
    all_pairs = exact_pairs + pseudo_pairs

    print(f"coverage={cov} known_ks={len(ks)} exact_pdf_samples={len(samples)}", flush=True)
    print(f"common_prefix_len={args.prefix_len} count={prefix_count} fraction={prefix_frac:.6f}", flush=True)
    print(f"exact_pairs={len(exact_pairs)} pseudo_pairs={len(pseudo_pairs)} max_gap={args.max_gap}", flush=True)
    for pair in exact_pairs:
        print(
            f"  EXACT gap={len(pair['missing'])} blocks={len(pair['expected_blocks'])} fei={pair['fei_len']} size={pair['body_end']} "
            f"missing={ranges(pair['missing'])} rel={pair['rel']}",
            flush=True,
        )
    for pair in pseudo_pairs:
        print(
            f"  PSEUDO gap={len(pair['missing'])} blocks={len(pair['expected_blocks'])} fei={pair['fei_len']} size={pair['body_end']} "
            f"missing={ranges(pair['missing'])} rel={pair['rel']}"
            ,
            flush=True,
        )

    words_list = [(0,), (1,), (2,), (3,), (14,), (15,), (7,), (8,), (0, 1), (14, 15), (0, 14), (0, 15)]
    words_list = words_list[: args.max_strategies]
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["status", "words", "pseudo_pairs", "unknown_bytes", "ks_offsets", "ks_hex", "full_verify"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for idx, words in enumerate(words_list, 1):
            print(f"{idx}/{len(words_list)} solving words={words} timeout_ms={args.timeout_ms}", flush=True)
            row = solve_strategy(ks, all_pairs, words, args.timeout_ms)
            writer.writerow(row)
            fh.flush()
            print(f"{idx}/{len(words_list)} words={words} status={row['status']} unknown={row['unknown_bytes']} full={row['full_verify']}", flush=True)
            if row["full_verify"] == "True":
                print(f"FOUND ks_offsets={row['ks_offsets']} ks_hex={row['ks_hex']}", flush=True)
                return 0
    print(f"report={args.out}", flush=True)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
