

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

TARGET_FOLDERS = ["АДМИНИСТРАЦИЯ", "Производство", "ЗАКУПКИ"]
SEARCH_ROOTS = [
    Path(_case_value('4cdf924bebda46a57d52')),
    Path(_case_value('4ad553a2014833d3f789')),
    Path(_case_value('793313ad8753ea27fb46')),
    Path(_case_value('f4e5e33bf20cc2d98993')),
]


def missing_items():
    wanted = {}
    items = []
    for folder in TARGET_FOLDERS:
        src = SRC_ROOT / folder
        if not src.exists():
            continue
        for enc in src.rglob("*" + EXT):
            rel = enc.relative_to(SRC_ROOT)
            plain_rel = Path(str(rel)[: -len(EXT)])
            out = OUT_ROOT / plain_rel
            if out.exists():
                continue
            plain_name = enc.name[: -len(EXT)]
            item = {
                "folder": folder,
                "encrypted": enc,
                "relative": plain_rel,
                "output": out,
                "plain_name": plain_name,
                "encrypted_size": enc.stat().st_size,
            }
            items.append(item)
            wanted.setdefault(plain_name.lower(), []).append(item)
    return items, wanted


def main() -> int:
    TECH.mkdir(parents=True, exist_ok=True)
    items, wanted = missing_items()
    report = TECH / "restored_exact_clones_multi.csv"
    rows = []
    restored = 0
    seen = 0
    print(f"MISSING_TOTAL {len(items)} WANTED_NAMES {len(wanted)}", flush=True)

    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        print(f"SCAN_ROOT {root}", flush=True)
        for dirpath, dirnames, filenames in os.walk(root):
            # Do not search inside recovered output if a junction/symlink appears.
            try:
                if OUT_ROOT in Path(dirpath).parents or Path(dirpath) == OUT_ROOT:
                    continue
            except OSError:
                pass
            for fn in filenames:
                seen += 1
                if fn.endswith(EXT):
                    continue
                hits = wanted.get(fn.lower())
                if not hits:
                    continue
                candidate = Path(dirpath) / fn
                try:
                    cand_size = candidate.stat().st_size
                except OSError:
                    continue
                for item in hits:
                    delta = item["encrypted_size"] - cand_size
                    action = "REJECT_SIZE"
                    if 100 <= delta <= 2000:
                        out = item["output"]
                        if out.exists():
                            action = "SKIP_EXISTS"
                        else:
                            out.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(candidate, out)
                            restored += 1
                            action = "RESTORED_CLONE"
                            print(f"RESTORED {item['folder']} delta={delta} {out}", flush=True)
                    rows.append({
                        "action": action,
                        "folder": item["folder"],
                        "delta": str(delta),
                        "candidate": str(candidate),
                        "encrypted": str(item["encrypted"]),
                        "output": str(item["output"]),
                    })
            if seen and seen % 50000 == 0:
                print(f"  seen={seen} restored={restored}", flush=True)

    with report.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["action", "folder", "delta", "candidate", "encrypted", "output"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"DONE seen={seen} restored={restored} report={report}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
