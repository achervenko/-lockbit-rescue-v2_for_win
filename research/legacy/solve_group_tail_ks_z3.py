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

import recover_desktop_tree as rdt
from solve_tail_fek_z3 import SRC_ROOT, EXT, REPORTS, build_group_ks, salsa20_words_z3, word_from_bytes

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return Path(_case_value('c2cb6ef3d173e2cf36a2')) / Path(str(rel)[: -len(EXT)])


def main() -> int:
    kek = sys.argv[1] if len(sys.argv) > 1 else _case_value('334d517b17c31441017e')
    max_missing = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    words_limit = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    timeout_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 30000

    ks, files = build_group_ks(kek)
    base_cov = rdt.contiguous(ks)
    pairs = []
    for item in files:
        enc = Path(item.path)
        out = output_path_for(enc)
        if not out.exists() or not out.is_file():
            continue
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
        if out.stat().st_size != body_end:
            continue
        fek_start = fei_len - 64
        missing = [off for off in range(fek_start, fei_len) if off not in ks]
        if 0 < len(missing) <= max_missing and min(missing) == base_cov:
            with enc.open("rb") as ef, out.open("rb") as pf:
                expected = bytes(a ^ b for a, b in zip(ef.read(64), pf.read(64)))
            if len(expected) == 64:
                pairs.append((item, fei_len, fei_ct, expected, missing))

    pairs.sort(key=lambda x: (len(x[4]), x[1], x[0].original_name.lower()))
    pairs = pairs[:12]
    if not pairs:
        print("no pairs")
        return 2

    max_off = max(max(missing) for *_, missing in pairs)
    unknown_ks = {off: z3.BitVec(f"ks{off}", 8) for off in range(base_cov, max_off + 1)}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)

    for item, fei_len, fei_ct, expected, missing in pairs:
        fek_start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = fek_start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
        state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
        out_words = salsa20_words_z3(state)
        for wi, word in enumerate(out_words[:words_limit]):
            expected_word = int.from_bytes(expected[wi * 4 : wi * 4 + 4], "little")
            solver.add(word == z3.BitVecVal(expected_word, 32))

    status = solver.check()
    row = {
        "status": str(status),
        "kek": kek,
        "base_cov": str(base_cov),
        "max_off": str(max_off),
        "unknown_bytes": str(max_off - base_cov + 1),
        "pairs": str(len(pairs)),
        "words_limit": str(words_limit),
    }
    if status == z3.sat:
        model = solver.model()
        vals = []
        for off in range(base_cov, max_off + 1):
            vals.append(model.eval(unknown_ks[off]).as_long())
        row["ks_hex"] = bytes(vals).hex()
    print(row)
    report = REPORTS / "z3_group_tail_ks_attempts.csv"
    exists = report.exists()
    with report.open("a", encoding="utf-8-sig", newline="") as f:
        fields = ["status", "kek", "base_cov", "max_off", "unknown_bytes", "pairs", "words_limit", "ks_hex"]
        w = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in fields})
    print(f"report={report}")
    return 0 if status == z3.sat else 2


if __name__ == "__main__":
    raise SystemExit(main())
