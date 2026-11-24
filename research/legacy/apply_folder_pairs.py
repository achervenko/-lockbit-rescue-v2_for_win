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


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def safe_name(text: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in text.lower())


def out_path_for(enc: Path) -> Path:
    rel = Path(str(enc.relative_to(SRC_ROOT))[: -len(EXT)])
    rename_parts = {"�11_inf": "М11_inf", "���_inf": "ЭДО_inf", "�11": "М11", "���": "ЭДО"}
    rel = Path(*[rename_parts.get(part, part) for part in rel.parts])
    return DST_ROOT / rel


def main() -> int:
    folder = os.environ.get("PAIR_TARGET_FOLDER")
    pair_root = os.environ.get("PAIR_ROOT")
    if not folder or not pair_root:
        print("ERROR: set PAIR_TARGET_FOLDER and PAIR_ROOT", file=sys.stderr)
        return 2

    target_root = SRC_ROOT / folder
    pair_root_path = Path(pair_root)
    REPORTS.mkdir(parents=True, exist_ok=True)

    by_name: dict[str, list[Path]] = defaultdict(list)
    for enc in target_root.rglob(f"*{EXT}"):
        by_name[enc.name[: -len(EXT)].lower()].append(enc)

    rows = []
    copied = 0
    skipped_exists = 0
    no_match = 0
    size_mismatch = 0
    read_errors = 0
    pair_files = [p for p in pair_root_path.rglob("*") if p.is_file()]

    for pair in sorted(pair_files, key=lambda p: str(p).lower()):
        matches = by_name.get(pair.name.lower(), [])
        if not matches:
            no_match += 1
            rows.append({
                "status": "NO_MATCH",
                "pair": str(pair),
                "encrypted": "",
                "out": "",
                "body_size": "",
                "pair_size": pair.stat().st_size,
            })
            continue

        matched_any = False
        for enc in matches:
            try:
                _, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            except Exception:
                read_errors += 1
                rows.append({
                    "status": "READ_ERROR",
                    "pair": str(pair),
                    "encrypted": str(enc),
                    "out": str(out_path_for(enc)),
                    "body_size": "",
                    "pair_size": pair.stat().st_size,
                })
                continue
            if pair.stat().st_size != body_end:
                rows.append({
                    "status": "SIZE_MISMATCH",
                    "pair": str(pair),
                    "encrypted": str(enc),
                    "out": str(out_path_for(enc)),
                    "body_size": body_end,
                    "pair_size": pair.stat().st_size,
                })
                continue

            matched_any = True
            out = out_path_for(enc)
            if out.exists():
                skipped_exists += 1
                rows.append({
                    "status": "SKIP_EXISTS",
                    "pair": str(pair),
                    "encrypted": str(enc),
                    "out": str(out),
                    "body_size": body_end,
                    "pair_size": pair.stat().st_size,
                })
                continue

            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(pair, out)
            copied += 1
            rows.append({
                "status": "COPIED_PAIR",
                "pair": str(pair),
                "encrypted": str(enc),
                "out": str(out),
                "body_size": body_end,
                "pair_size": pair.stat().st_size,
            })

        if not matched_any:
            size_mismatch += 1

    report = REPORTS / f"pairs_apply_report_{safe_name(folder)}_{safe_name(pair_root_path.name)}.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["status", "pair", "encrypted", "out", "body_size", "pair_size"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"folder={folder}")
    print(f"pair_files={len(pair_files)}")
    print(f"copied={copied}")
    print(f"skipped_exists={skipped_exists}")
    print(f"no_match={no_match}")
    print(f"size_mismatch_files={size_mismatch}")
    print(f"read_errors={read_errors}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
