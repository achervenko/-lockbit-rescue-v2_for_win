

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import os, re, csv

telegram = Path(_case_value('793313ad8753ea27fb46'))
public = Path(_case_value('4cdf924bebda46a57d52'))
out = Path(_case_value('f024f29275d747745c37'))
ext = ".xzg9VRelb"
locals=[]
for p in telegram.rglob("*"):
    if not p.is_file() or p.name.endswith(ext) or p.suffix.lower()==".rar":
        continue
    stem = p.stem.lower()
    tokens = [t for t in re.split(r"[\s_\-.,()]+", stem) if len(t) >= 4]
    locals.append((p, p.stat().st_size, set(tokens)))
rows=[]
seen=0
for dirpath, dirnames, filenames in os.walk(public):
    for fn in filenames:
        if not fn.endswith(ext):
            continue
        seen += 1
        low = fn[:-len(ext)].lower()
        try:
            size = (Path(dirpath)/fn).stat().st_size
        except OSError:
            continue
        for lp, lsize, toks in locals:
            if abs((size - lsize)) > 600:
                continue
            score = sum(1 for t in toks if t in low)
            if score >= 2 or lp.name.lower() in low:
                rows.append({"score":score,"local":str(lp),"local_size":lsize,"public":str(Path(dirpath)/fn),"public_size":size,"delta":size-lsize})
rows.sort(key=lambda r:(-r["score"], abs(r["delta"]), r["public"]))
with out.open("w", encoding="utf-8-sig", newline="") as f:
    w=csv.DictWriter(f, fieldnames=["score","local","local_size","public","public_size","delta"])
    w.writeheader(); w.writerows(rows)
print(f"encrypted_seen={seen} candidates={len(rows)} report={out}")
for r in rows[:40]:
    print(f"CAND score={r['score']} delta={r['delta']} local={Path(r['local']).name} public={r['public']}")
