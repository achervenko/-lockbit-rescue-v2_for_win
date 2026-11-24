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
import itertools
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
TARGET = SRC_ROOT / "СКЛАД" / "Сканы документов" / "2025" / "2511" / _case_value('586dece1bf9289e9b4e7')


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def find_item(enc: Path):
    groups, _, _ = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    for kek, files in groups.items():
        for item in files:
            if Path(item.path) == enc:
                return kek, files, item
    raise RuntimeError("target not found")


def build_ks(files):
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump base ks")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def add_word_constraints(solver, out_words, expected, word_indices):
    for wi in word_indices:
        expected_word = int.from_bytes(expected[wi * 4 : wi * 4 + 4], "little")
        solver.add(out_words[wi] == z3.BitVecVal(expected_word, 32))


def solve_strategy(word_indices: tuple[int, ...], timeout_ms: int, max_models: int) -> dict[str, str]:
    kek, files, item = find_item(TARGET)
    ks = build_ks(files)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(TARGET)
    out = output_path_for(TARGET)
    if not out.exists() or out.stat().st_size != body_end:
        raise RuntimeError("known pair missing or size mismatch")

    fek_start = fei_len - 64
    known_fek = []
    missing_positions = []
    for i in range(64):
        off = fek_start + i
        if off in ks:
            known_fek.append(fei_ct[off] ^ ks[off])
        else:
            known_fek.append(None)
            missing_positions.append(i)

    with TARGET.open("rb") as ef, out.open("rb") as pf:
        expected = bytes(a ^ b for a, b in zip(ef.read(64), pf.read(64)))
    if len(expected) != 64:
        raise RuntimeError("need first 64 bytes")

    unknowns = {pos: z3.BitVec(f"b{pos}", 8) for pos in missing_positions}
    fek_bytes = [unknowns[i] if b is None else b for i, b in enumerate(known_fek)]
    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    out_words = salsa20_words_z3(state)

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    add_word_constraints(solver, out_words, expected, word_indices)

    models_checked = 0
    while models_checked < max_models:
        status = solver.check()
        if status != z3.sat:
            return {
                "status": str(status),
                "word_indices": ",".join(map(str, word_indices)),
                "models_checked": str(models_checked),
                "kek": kek,
                "missing_positions": ",".join(map(str, missing_positions)),
            }
        model = solver.model()
        candidate = bytearray(64)
        for i, b in enumerate(known_fek):
            candidate[i] = model.eval(unknowns[i]).as_long() if b is None else b
        models_checked += 1
        if rdt.salsa20_block(bytes(candidate)) == expected:
            return {
                "status": "sat_full_verify",
                "word_indices": ",".join(map(str, word_indices)),
                "models_checked": str(models_checked),
                "kek": kek,
                "missing_positions": ",".join(map(str, missing_positions)),
                "fek_hex": bytes(candidate).hex(),
            }
        # Block this exact assignment of the unknown bytes and ask for another.
        solver.add(z3.Or([unknowns[pos] != model.eval(unknowns[pos]) for pos in missing_positions]))
    return {
        "status": "sat_partial_no_full_model",
        "word_indices": ",".join(map(str, word_indices)),
        "models_checked": str(models_checked),
        "kek": kek,
        "missing_positions": ",".join(map(str, missing_positions)),
    }


def main() -> int:
    timeout_ms = int(sys.argv[1]) if len(sys.argv) > 1 else 30_000
    max_models = int(sys.argv[2]) if len(sys.argv) > 2 else 64
    max_attempts = int(sys.argv[3]) if len(sys.argv) > 3 else 40

    # Prioritize word pairs spread across Salsa20 output rather than only prefix.
    priority = [
        (14, 15), (0, 15), (0, 1), (7, 8), (3, 12), (5, 10),
        (1, 14), (2, 15), (4, 13), (6, 11), (8, 15), (0, 7),
    ]
    all_pairs = list(itertools.combinations(range(16), 2))
    strategies = []
    for pair in priority + all_pairs:
        if pair not in strategies:
            strategies.append(pair)
    strategies = strategies[:max_attempts]

    REPORTS.mkdir(parents=True, exist_ok=True)
    report = REPORTS / "sklad_4f_z3_word_strategy.csv"
    exists = report.exists()
    fields = ["status", "word_indices", "models_checked", "kek", "missing_positions", "fek_hex"]
    with report.open("a", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        for idx, strategy in enumerate(strategies, 1):
            row = solve_strategy(strategy, timeout_ms, max_models)
            writer.writerow({field: row.get(field, "") for field in fields})
            fh.flush()
            print(f"{idx}/{len(strategies)} {row}", flush=True)
            if row.get("status") == "sat_full_verify":
                print(f"report={report}")
                return 0
    print(f"report={report}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
