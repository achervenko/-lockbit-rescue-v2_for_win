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
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
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


def load_seed(seed_path: Path) -> dict[int, int]:
    import json

    data = json.loads(seed_path.read_text(encoding="utf-8"))
    group = data["groups"][KEK]
    return {int(off): int(hex_byte, 16) for off, hex_byte in group["ks"].items()}


def encrypted_ranges(body_len: int, before: int = 3, after: int = 3, skipped: int = 0x520000) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    cur = 0
    decrypt_remaining = before
    is_skip = False
    chunk = 0x20000
    while cur < body_len:
        if is_skip:
            cur = min(body_len, cur + skipped)
            decrypt_remaining = after
            is_skip = False
            continue
        want = min(chunk, body_len - cur)
        ranges.append((cur, want))
        cur += want
        if decrypt_remaining == 0:
            is_skip = True
        else:
            decrypt_remaining -= 1
    return ranges


def collect_pairs(seed_path: Path, pair_limit: int, block_indexes: tuple[int, ...]) -> tuple[dict[int, int], list[dict[str, object]]]:
    ks = load_seed(seed_path)
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups.get(KEK, [])
    cov = rdt.contiguous(ks)
    rows: list[tuple[int, int, str, dict[str, object]]] = []
    for item in files:
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
        if missing != list(range(cov, cov + 11)):
            continue
        with Path(item.path).open("rb") as ef, out.open("rb") as pf:
            enc_body = ef.read(body_end)
            plain_body = pf.read(body_end)
        if len(enc_body) != body_end or len(plain_body) != body_end:
            continue
        body_stream = bytes(a ^ b for a, b in zip(enc_body, plain_body))
        ranges = encrypted_ranges(body_end)
        continuous_prefix = ranges[0][1] if ranges and ranges[0][0] == 0 else 0
        expected_blocks: dict[int, str] = {}
        for block_index in block_indexes:
            off = block_index * 64
            if off + 64 > continuous_prefix:
                continue
            expected_blocks[block_index] = body_stream[off : off + 64].hex()
        if set(expected_blocks) != set(block_indexes):
            continue
        rows.append(
            (
                len(missing),
                fei_len,
                item.original_name.lower(),
                {
                    "name": item.original_name,
                    "path": item.path,
                    "fei_len": fei_len,
                    "fei_ct_hex": fei_ct.hex(),
                    "expected_blocks": expected_blocks,
                },
            )
        )
    rows.sort()
    return ks, [row[-1] for row in rows[:pair_limit]]


def solve_cube(task: dict[str, object]) -> dict[str, str]:
    ks: dict[int, int] = task["ks"]  # type: ignore[assignment]
    pairs: list[dict[str, object]] = task["pairs"]  # type: ignore[assignment]
    cube_offsets: tuple[int, ...] = task["cube_offsets"]  # type: ignore[assignment]
    cube_values: tuple[int, ...] = task["cube_values"]  # type: ignore[assignment]
    words: tuple[int, ...] = task["words"]  # type: ignore[assignment]
    block_indexes: tuple[int, ...] = task["block_indexes"]  # type: ignore[assignment]
    timeout_ms = int(task["timeout_ms"])

    cov = rdt.contiguous(ks)
    max_off = cov + 10
    unknown = {off: z3.BitVec(f"ks_{off}", 8) for off in range(cov, max_off + 1) if off not in ks}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    solver.set("random_seed", int.from_bytes(bytes(cube_values[:4]).ljust(4, b"\0"), "little"))

    for off, val in zip(cube_offsets, cube_values):
        solver.add(unknown[off] == z3.BitVecVal(val, 8))

    for pair in pairs:
        fei_len = int(pair["fei_len"])
        fei_ct = bytes.fromhex(str(pair["fei_ct_hex"]))
        expected_blocks: dict[int, str] = pair["expected_blocks"]  # type: ignore[assignment]
        start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])
        base_state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
        for block_index in block_indexes:
            expected = bytes.fromhex(expected_blocks[block_index])
            state = base_state[:]
            state[8] = state[8] + z3.BitVecVal(block_index, 32)
            out_words = salsa20_words_z3(state)
            for wi in words:
                solver.add(out_words[wi] == z3.BitVecVal(int.from_bytes(expected[wi * 4 : wi * 4 + 4], "little"), 32))

    status = solver.check()
    row = {
        "status": str(status),
        "cube_offsets": ",".join(map(str, cube_offsets)),
        "cube_values": "".join(f"{v:02x}" for v in cube_values),
        "words": ",".join(map(str, words)),
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
        fei_ct = bytes.fromhex(str(pair["fei_ct_hex"]))
        expected_blocks: dict[int, str] = pair["expected_blocks"]  # type: ignore[assignment]
        start = fei_len - 64
        fek = bytearray(64)
        for i in range(64):
            off = start + i
            ksb = ks[off] if off in ks else vals[off]
            fek[i] = fei_ct[off] ^ ksb
        for block_index in block_indexes:
            expected = bytes.fromhex(expected_blocks[block_index])
            state = [
                int.from_bytes(fek[i * 4 : i * 4 + 4], "little")
                for i in range(16)
            ]
            state[8] = (state[8] + block_index) & 0xFFFFFFFF
            got = rdt.salsa20_block(b"".join(v.to_bytes(4, "little") for v in state))
            if got != expected:
                ok = False
                break
        if not ok:
            break
    row["full_verify"] = str(ok)
    return row


def read_done(report: Path) -> set[str]:
    if not report.exists():
        return set()
    done = set()
    with report.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            done.add(row["cube_values"])
    return done


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed-json", type=Path, default=REPORTS / "sklad_z3_keystream_seed.json")
    parser.add_argument("--cube-bytes", type=int, default=1, choices=[1, 2])
    parser.add_argument("--pairs", type=int, default=3)
    parser.add_argument("--words", default="0", help="Comma-separated Salsa20 word indexes, e.g. 0 or 0,1")
    parser.add_argument("--blocks", default="0", help="Comma-separated Salsa20 block indexes, e.g. 0 or 0,1,2")
    parser.add_argument("--timeout-ms", type=int, default=20_000)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--limit-cubes", type=int, default=0)
    parser.add_argument("--report", type=Path, default=REPORTS / "z3_cube_624_tail_worker.csv")
    args = parser.parse_args()

    REPORTS.mkdir(parents=True, exist_ok=True)
    block_indexes = tuple(int(part.strip()) for part in args.blocks.split(",") if part.strip())
    ks, pairs = collect_pairs(args.seed_json, args.pairs, block_indexes)
    cov = rdt.contiguous(ks)
    if cov != 106 or len(pairs) < 1:
        raise RuntimeError(f"unexpected setup: cov={cov} pairs={len(pairs)}")

    words = tuple(int(part.strip()) for part in args.words.split(",") if part.strip())
    cube_offsets = tuple(range(cov, cov + args.cube_bytes))
    done = read_done(args.report)
    fields = ["status", "cube_offsets", "cube_values", "words", "ks_hex", "full_verify", "elapsed_sec"]

    all_values = itertools.product(range(256), repeat=args.cube_bytes)
    tasks = []
    for values in all_values:
        cube_key = "".join(f"{v:02x}" for v in values)
        if cube_key in done:
            continue
        tasks.append(
            {
                "ks": ks,
                "pairs": pairs,
                "cube_offsets": cube_offsets,
                "cube_values": values,
                "words": words,
                "block_indexes": block_indexes,
                "timeout_ms": args.timeout_ms,
            }
        )
        if args.limit_cubes and len(tasks) >= args.limit_cubes:
            break

    print(
        f"KEK={KEK} cov={cov} missing=106-116 pairs={len(pairs)} "
        f"cube_offsets={cube_offsets} blocks={block_indexes} pending={len(tasks)} "
        f"workers={args.workers} timeout_ms={args.timeout_ms}",
        flush=True,
    )
    for p in pairs:
        print(f"PAIR {p['name']}", flush=True)

    exists = args.report.exists()
    solved = False
    started = time.time()
    with args.report.open("a", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = {pool.submit(solve_cube, task): task for task in tasks}
            for idx, fut in enumerate(as_completed(futures), 1):
                row = fut.result()
                row["elapsed_sec"] = f"{time.time() - started:.1f}"
                writer.writerow({field: row.get(field, "") for field in fields})
                fh.flush()
                if idx % 10 == 0 or row.get("full_verify") == "True":
                    print(
                        f"{idx}/{len(tasks)} status={row['status']} cube={row['cube_values']} "
                        f"full={row.get('full_verify','')} elapsed={row['elapsed_sec']}s",
                        flush=True,
                    )
                if row.get("full_verify") == "True":
                    print(f"FOUND ks_hex={row['ks_hex']} cube={row['cube_values']}", flush=True)
                    solved = True
                    pool.shutdown(cancel_futures=True)
                    break
    print(f"report={args.report}", flush=True)
    return 0 if solved else 2


if __name__ == "__main__":
    raise SystemExit(main())
