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
import shutil
from pathlib import Path

ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
OUT_ROOT = ROOT / "ЗАКУПКИ"
REPORTS = ROOT / "_technical_reports"

PAIRS = [
    (
        Path(_case_value('114ff0e7af8aeebbbf95')),
        Path(_case_value('0285223511c81d05b74b')),
        "same_size_valid_xlsx_same_folder_similarity_0.898",
    ),
]


def main() -> int:
    rows = []
    restored = 0
    for target_rel, source_rel, reason in PAIRS:
        target = OUT_ROOT / target_rel
        source = OUT_ROOT / source_rel
        if target.exists():
            rows.append({"status": "SKIPPED_EXISTS", "target": str(target_rel), "source": str(source_rel), "reason": reason})
            continue
        if not source.exists():
            rows.append({"status": "SOURCE_MISSING", "target": str(target_rel), "source": str(source_rel), "reason": reason})
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        restored += 1
        rows.append({"status": "RESTORED_PROBABLE_CLONE", "target": str(target_rel), "source": str(source_rel), "reason": reason})
        print(f"RESTORED_PROBABLE_CLONE {target_rel} <- {source_rel}", flush=True)

    report = REPORTS / "ЗАКУПКИ_probable_doc_clones_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["status", "target", "source", "reason"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"restored={restored}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
