

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import csv, shutil

manifest = Path(_case_value('7bdab8cd2b71a4d0849d'))
src_public_root = _case_value('4cdf924bebda46a57d52')
local_src_root = Path(_case_value('f6af7da1ad90629ee69b'))
out_root = Path(_case_value('c2cb6ef3d173e2cf36a2'))
ext = ".xzg9VRelb"

added = 0
skipped = 0
not_local = 0
rows = list(csv.DictReader(manifest.open("r", encoding="utf-8-sig")))
for row in rows:
    public = Path(row["public"])
    local_original = Path(row["local"])
    public_s = str(public)
    if not public_s.lower().startswith(src_public_root.lower()):
        continue
    rel = public_s[len(src_public_root):].lstrip("\\/")
    local_encrypted = local_src_root / rel
    if not local_encrypted.exists():
        not_local += 1
        continue
    if not str(local_encrypted).startswith(str(local_src_root / "АДМИНИСТРАЦИЯ")):
        continue
    out_rel = Path(rel[:-len(ext)] if rel.endswith(ext) else rel)
    out = out_root / out_rel
    if out.exists():
        skipped += 1
        print(f"SKIP_EXISTS\t{out}")
        continue
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(local_original, out)
    added += 1
    print(f"RESTORED_FROM_PAIR\t{out}")
print(f"DONE added={added} skipped_exists={skipped} not_local={not_local}")
