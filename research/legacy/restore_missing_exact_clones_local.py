

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import csv
import os
import shutil


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
TECH = OUT_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"

SEARCH_ROOTS = [
    Path(_case_value('4ad553a2014833d3f789')),
    Path(_case_value('793313ad8753ea27fb46')),
    Path(_case_value('f4e5e33bf20cc2d98993')),
]


def main() -> int:
    TECH.mkdir(parents=True, exist_ok=True)
    wanted = {}
    missing = 0
    for folder in SRC_ROOT.iterdir():
        if not folder.is_dir():
            continue
        for enc in folder.rglob("*" + EXT):
            rel = enc.relative_to(SRC_ROOT)
            out = OUT_ROOT / Path(str(rel)[: -len(EXT)])
            if out.exists():
                continue
            missing += 1
            plain_name = enc.name[: -len(EXT)]
            wanted.setdefault(plain_name.lower(), []).append((enc, out, folder.name, enc.stat().st_size))

    rows = []
    restored = 0
    print(f"MISSING {missing} WANTED_NAMES {len(wanted)}", flush=True)
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        print(f"SCAN_ROOT {root}", flush=True)
        for dirpath, _, filenames in os.walk(root):
            for fn in filenames:
                if fn.endswith(EXT):
                    continue
                for enc, out, folder_name, enc_size in wanted.get(fn.lower(), []):
                    candidate = Path(dirpath) / fn
                    try:
                        delta = enc_size - candidate.stat().st_size
                    except OSError:
                        continue
                    action = "REJECT_SIZE"
                    if 100 <= delta <= 2000:
                        if out.exists():
                            action = "SKIP_EXISTS"
                        else:
                            out.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(candidate, out)
                            restored += 1
                            action = "RESTORED_CLONE"
                            print(f"RESTORED {folder_name} delta={delta} {out}", flush=True)
                    rows.append({
                        "action": action,
                        "folder": folder_name,
                        "delta": delta,
                        "candidate": str(candidate),
                        "encrypted": str(enc),
                        "output": str(out),
                    })

    report = TECH / "restored_exact_clones_local.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["action", "folder", "delta", "candidate", "encrypted", "output"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"DONE restored={restored} report={report}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
