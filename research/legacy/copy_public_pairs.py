

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import os, shutil, csv, re

telegram = Path(_case_value('793313ad8753ea27fb46'))
public_root = Path(_case_value('4cdf924bebda46a57d52'))
pairs_out = Path(_case_value('b9ac0e0cdf2118cb85e6'))
manifest = pairs_out / "found_pairs.csv"
ext = ".xzg9VRelb"

pairs_out.mkdir(parents=True, exist_ok=True)
local_files = [p for p in telegram.rglob("*") if p.is_file()]
wanted = {}
for p in local_files:
    name = p.name
    if name.lower().endswith(".rar"):
        continue
    if name.endswith(ext):
        wanted.setdefault(name[:-len(ext)].lower(), []).append(("need_plain", p))
    else:
        wanted.setdefault((name + ext).lower(), []).append(("need_encrypted", p))

def safe(s):
    s = re.sub(r'[<>:"/\\|?*]+', '_', s)
    return s[:120]

rows=[]
for dirpath, dirnames, filenames in os.walk(public_root):
    for fn in filenames:
        for kind, local in wanted.get(fn.lower(), []):
            public = Path(dirpath) / fn
            rel_parent = public.parent.relative_to(public_root)
            tag = safe(str(rel_parent)) or "public_root"
            stem = safe(local.name[:-len(ext)] if local.name.endswith(ext) else local.name)
            sub = pairs_out / f"{stem}__{tag}"
            sub.mkdir(parents=True, exist_ok=True)
            if kind == "need_encrypted":
                plain_dst = sub / local.name
                enc_dst = sub / public.name
                if not plain_dst.exists():
                    shutil.copy2(local, plain_dst)
                if not enc_dst.exists():
                    shutil.copy2(public, enc_dst)
            else:
                enc_dst = sub / local.name
                plain_dst = sub / public.name
                if not enc_dst.exists():
                    shutil.copy2(local, enc_dst)
                if not plain_dst.exists():
                    shutil.copy2(public, plain_dst)
            rows.append({"kind":kind,"local":str(local),"public":str(public),"pair_dir":str(sub)})
            print(f"COPIED\t{kind}\t{sub}")
with manifest.open("w", encoding="utf-8-sig", newline="") as f:
    w=csv.DictWriter(f, fieldnames=["kind","local","public","pair_dir"])
    w.writeheader(); w.writerows(rows)
print(f"DONE copied_pairs={len(rows)} manifest={manifest}")
