

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import os, shutil

telegram = Path(_case_value('793313ad8753ea27fb46'))
public_roots = [Path(_case_value('4cdf924bebda46a57d52'))]
pairs_dir = Path(_case_value('f4e5e33bf20cc2d98993'))
ext = ".xzg9VRelb"

local_files = [p for p in telegram.rglob("*") if p.is_file()]
wanted = {}
for p in local_files:
    name = p.name
    if name.lower().endswith(".rar"):
        continue
    if name.endswith(ext):
        plain = name[:-len(ext)]
        wanted.setdefault(plain.lower(), []).append(("need_plain", p))
    else:
        wanted.setdefault((name + ext).lower(), []).append(("need_encrypted", p))

print(f"LOCAL_FILES {len(local_files)}")
print(f"WANTED_NAMES {len(wanted)}")
found = []
seen_dirs = 0
seen_files = 0
for root in public_roots:
    print(f"SCAN_ROOT {root}", flush=True)
    for dirpath, dirnames, filenames in os.walk(root):
        seen_dirs += 1
        if seen_dirs % 1000 == 0:
            print(f"  scanned_dirs={seen_dirs} files={seen_files} found={len(found)}", flush=True)
        for fn in filenames:
            seen_files += 1
            hit = wanted.get(fn.lower())
            if not hit:
                continue
            full = Path(dirpath) / fn
            for kind, local in hit:
                found.append((kind, local, full))
                print(f"FOUND {kind}\tLOCAL={local}\tPUBLIC={full}", flush=True)
print(f"DONE dirs={seen_dirs} files={seen_files} found={len(found)}")
