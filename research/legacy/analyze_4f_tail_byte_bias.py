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
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"
KEK = _case_value('334d517b17c31441017e')


def entropy(counter: Counter[int]) -> float:
    n = sum(counter.values())
    if not n:
        return 0.0
    return -sum((v / n) * math.log2(v / n) for v in counter.values())


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    files = groups[KEK]
    by_abs: dict[int, Counter[int]] = defaultdict(Counter)
    by_rel: dict[int, Counter[int]] = defaultdict(Counter)
    rows = []
    for item in files:
        p = Path(item.path)
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(p)
        fek_start = fei_len - 64
        for off in range(max(0, fek_start), fei_len):
            val = fei_ct[off]
            by_abs[off][val] += 1
            by_rel[off - fek_start][val] += 1
        # targeted absolute offsets around the current wall
        vals_108_113 = []
        for off in range(108, 114):
            if off < len(fei_ct):
                vals_108_113.append(f"{off}:{fei_ct[off]:02x}")
        rows.append(
            {
                "name": item.original_name,
                "path": item.path,
                "fei_len": fei_len,
                "fek_start": fek_start,
                "body_size": body_end,
                "coverage": item.coverage,
                "tail_abs_108_113_cipher": " ".join(vals_108_113),
            }
        )

    abs_rows = []
    for off in range(90, 130):
        c = by_abs.get(off, Counter())
        if not c:
            continue
        abs_rows.append(
            {
                "abs_off": off,
                "samples": sum(c.values()),
                "unique": len(c),
                "entropy": f"{entropy(c):.4f}",
                "top": ";".join(f"{b:02x}:{n}" for b, n in c.most_common(8)),
            }
        )
    rel_rows = []
    for pos in range(64):
        c = by_rel.get(pos, Counter())
        if not c:
            continue
        rel_rows.append(
            {
                "fek_pos": pos,
                "samples": sum(c.values()),
                "unique": len(c),
                "entropy": f"{entropy(c):.4f}",
                "top": ";".join(f"{b:02x}:{n}" for b, n in c.most_common(8)),
            }
        )

    for path, data in [
        (REPORTS / "sklad_4f_tail_abs_bias.csv", abs_rows),
        (REPORTS / "sklad_4f_tail_rel_bias.csv", rel_rows),
        (REPORTS / "sklad_4f_tail_per_file.csv", rows),
    ]:
        with path.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()))
            writer.writeheader()
            writer.writerows(data)
        print(f"wrote={path}")

    print("ABS_OFFSETS_108_113")
    for row in abs_rows:
        if 108 <= int(row["abs_off"]) <= 113:
            print(row)
    print("FEK_POS_58_63")
    for row in rel_rows:
        if 58 <= int(row["fek_pos"]) <= 63:
            print(row)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
