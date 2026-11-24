

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import os, csv, shutil

src_root = Path(_case_value('f6af7da1ad90629ee69b'))
admin = src_root / "АДМИНИСТРАЦИЯ"
out_root = Path(_case_value('c2cb6ef3d173e2cf36a2'))
report = out_root / "public_original_clone_hits_admin.csv"
ext = ".xzg9VRelb"
search_roots = [
    Path(_case_value('4cdf924bebda46a57d52')),
    Path(_case_value('4ad553a2014833d3f789')),
    Path(_case_value('793313ad8753ea27fb46')),
]

missing = []
wanted = {}
for enc in admin.rglob("*" + ext):
    rel = enc.relative_to(src_root)
    out = out_root / Path(str(rel)[:-len(ext)])
    if out.exists():
        continue
    plain_name = enc.name[:-len(ext)]
    item = (enc, rel, out, plain_name)
    missing.append(item)
    wanted.setdefault(plain_name.lower(), []).append(item)

print(f"MISSING {len(missing)} WANTED_NAMES {len(wanted)}", flush=True)
rows=[]
added=0
seen=0
for root in search_roots:
    if not root.exists():
        continue
    print(f"SCAN_ROOT {root}", flush=True)
    for dirpath, dirnames, filenames in os.walk(root):
        # Avoid walking the output tree if Downloads ever links oddly.
        for fn in filenames:
            seen += 1
            if fn.endswith(ext):
                continue
            hits = wanted.get(fn.lower())
            if not hits:
                continue
            candidate = Path(dirpath) / fn
            try:
                cand_size = candidate.stat().st_size
            except OSError:
                continue
            for enc, rel, out, plain_name in hits:
                # LockBit encrypted size should be plaintext + FEI/footer-ish. Keep broad enough for exact clones.
                try:
                    enc_size = enc.stat().st_size
                except OSError:
                    continue
                delta = enc_size - cand_size
                if not (100 <= delta <= 1000):
                    rows.append({"action":"REJECT_SIZE", "candidate":str(candidate), "encrypted":str(enc), "delta":delta})
                    continue
                if out.exists():
                    rows.append({"action":"SKIP_EXISTS", "candidate":str(candidate), "encrypted":str(enc), "delta":delta})
                    continue
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(candidate, out)
                added += 1
                rows.append({"action":"RESTORED_CLONE", "candidate":str(candidate), "encrypted":str(enc), "output":str(out), "delta":delta})
                print(f"RESTORED_CLONE delta={delta}\t{out}", flush=True)
        if seen and seen % 50000 == 0:
            print(f"  seen={seen} added={added}", flush=True)

with report.open("w", encoding="utf-8-sig", newline="") as f:
    fields=["action","candidate","encrypted","output","delta"]
    w=csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for r in rows:
        w.writerow({k:r.get(k,"") for k in fields})
print(f"DONE seen={seen} added={added} report={report}", flush=True)
