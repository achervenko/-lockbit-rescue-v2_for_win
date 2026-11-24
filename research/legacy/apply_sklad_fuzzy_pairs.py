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
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr


PAIR_ROOT = Path(os.environ.get("SKLAD_PAIR_ROOT", _case_value('708880138eeb8dd2e078')))
SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
SKLAD_ROOT = SRC_ROOT / "СКЛАД"
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def out_path_for(enc: Path) -> Path:
    return DST_ROOT / Path(str(enc.relative_to(SRC_ROOT))[: -len(EXT)])


def normalize_stem(name: str) -> str:
    stem = Path(name).stem.lower()
    stem = re.sub(r"\s+", "", stem)
    stem = re.sub(r"[_\-\s]*(?:\(\d+\)|_\d+)$", "", stem)
    return stem


def date_prefix(name: str) -> str:
    m = re.match(r"^(\d{6})", Path(name).stem)
    return m.group(1) if m else ""


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)

    encrypted_rows = []
    by_size: dict[int, list[dict]] = defaultdict(list)
    for enc in SKLAD_ROOT.rglob(f"*{EXT}"):
        try:
            _, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
        except Exception:
            continue
        if out_path_for(enc).exists():
            continue
        plain_name = enc.name[: -len(EXT)]
        row = {
            "enc": enc,
            "body_size": body_end,
            "name": plain_name,
            "norm": normalize_stem(plain_name),
            "date": date_prefix(plain_name),
        }
        encrypted_rows.append(row)
        by_size[body_end].append(row)

    copied = 0
    rows = []
    for pair in sorted([p for p in PAIR_ROOT.rglob("*") if p.is_file()], key=lambda p: str(p).lower()):
        pair_size = pair.stat().st_size
        pair_norm = normalize_stem(pair.name)
        pair_date = date_prefix(pair.name)
        candidates = by_size.get(pair_size, [])
        if not candidates:
            continue

        strong = []
        for cand in candidates:
            same_date = pair_date and pair_date == cand["date"]
            same_norm = pair_norm == cand["norm"]
            contains = pair_norm in cand["norm"] or cand["norm"] in pair_norm
            if same_norm or (same_date and contains):
                strong.append(cand)

        if len(strong) != 1:
            if strong:
                rows.append({
                    "status": "AMBIGUOUS",
                    "pair": str(pair),
                    "pair_size": pair_size,
                    "candidates": " | ".join(str(c["enc"]) for c in strong[:10]),
                })
            continue

        cand = strong[0]
        out = out_path_for(cand["enc"])
        if out.exists():
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pair, out)
        copied += 1
        rows.append({
            "status": "COPIED_FUZZY_PAIR",
            "pair": str(pair),
            "pair_size": pair_size,
            "encrypted": str(cand["enc"]),
            "out": str(out),
        })

    report = REPORTS / "sklad_fuzzy_pairs_apply_report.csv"
    fields = sorted({key for row in rows for key in row}) if rows else ["status"]
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"remaining_encrypted_indexed={len(encrypted_rows)}")
    print(f"copied={copied}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
