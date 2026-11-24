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


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    by_name: dict[str, list[Path]] = defaultdict(list)
    for enc in SKLAD_ROOT.rglob(f"*{EXT}"):
        by_name[enc.name[: -len(EXT)].lower()].append(enc)

    rows = []
    copied = 0
    skipped_exists = 0
    no_match = 0
    size_mismatch = 0
    pair_files = [p for p in PAIR_ROOT.rglob("*") if p.is_file()]

    for pair in sorted(pair_files, key=lambda p: str(p).lower()):
        matches = by_name.get(pair.name.lower(), [])
        if not matches:
            no_match += 1
            rows.append({"status": "NO_MATCH", "pair": str(pair), "encrypted": "", "out": "", "body_size": "", "pair_size": pair.stat().st_size})
            continue

        matched_any = False
        for enc in matches:
            try:
                _, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            except Exception:
                continue
            if pair.stat().st_size != body_end:
                rows.append({"status": "SIZE_MISMATCH", "pair": str(pair), "encrypted": str(enc), "out": str(out_path_for(enc)), "body_size": body_end, "pair_size": pair.stat().st_size})
                continue

            matched_any = True
            out = out_path_for(enc)
            if out.exists():
                skipped_exists += 1
                rows.append({"status": "SKIP_EXISTS", "pair": str(pair), "encrypted": str(enc), "out": str(out), "body_size": body_end, "pair_size": pair.stat().st_size})
                continue

            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pair, out)
            copied += 1
            rows.append({"status": "COPIED_PAIR", "pair": str(pair), "encrypted": str(enc), "out": str(out), "body_size": body_end, "pair_size": pair.stat().st_size})

        if not matched_any:
            size_mismatch += 1

    safe_pair_name = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in PAIR_ROOT.name.lower())
    report = REPORTS / f"sklad_pairs_apply_report_{safe_pair_name}.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["status", "pair", "encrypted", "out", "body_size", "pair_size"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"pair_files={len(pair_files)}")
    print(f"copied={copied}")
    print(f"skipped_exists={skipped_exists}")
    print(f"no_match={no_match}")
    print(f"size_mismatch_files={size_mismatch}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
