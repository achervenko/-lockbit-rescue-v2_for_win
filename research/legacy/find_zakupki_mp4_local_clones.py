from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import hashlib
import os
import sys
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
SEARCH_ROOTS = [
    Path(_case_value('ae6d6877603b6a945206')),
    Path(_case_value('4ad553a2014833d3f789')),
]
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def quick_sig(path: Path) -> tuple[int, bytes, bytes]:
    size = path.stat().st_size
    with path.open("rb") as f:
        head = f.read(65536)
        if size > 65536:
            f.seek(max(0, size - 65536))
            tail = f.read(65536)
        else:
            tail = b""
    return size, hashlib.sha1(head).digest(), hashlib.sha1(tail).digest()


def main() -> int:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    targets = []
    names = set()
    sizes = set()
    for files in groups.values():
        for item in files:
            enc = Path(item.path)
            rel = out_rel_for(enc)
            if rel.suffix.lower() != ".mp4" or (OUT_ROOT / rel).exists():
                continue
            fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            targets.append((rel.name.lower(), body_end, enc, rel))
            names.add(rel.name.lower())
            sizes.add(body_end)

    print(f"mp4_targets={len(targets)} unique_names={len(names)}")
    candidates = []
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.mp4"):
            if ".xzg9VRelb" in path.name:
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            lname = path.name.lower()
            if lname in names or st.st_size in sizes:
                candidates.append((lname, st.st_size, path))

    print(f"local_candidates={len(candidates)}")
    by_name_size = {(name, size): (enc, rel) for name, size, enc, rel in targets}
    by_name = {}
    by_size = {}
    for name, size, enc, rel in targets:
        by_name.setdefault(name, []).append((size, enc, rel))
        by_size.setdefault(size, []).append((name, enc, rel))

    hits = []
    for lname, size, path in candidates:
        reason = None
        matched = []
        if (lname, size) in by_name_size:
            matched.append(by_name_size[(lname, size)])
            reason = "name+size"
        elif lname in by_name:
            matched.extend((enc, rel) for _, enc, rel in by_name[lname])
            reason = "name"
        elif size in by_size:
            matched.extend((enc, rel) for _, enc, rel in by_size[size])
            reason = "size"
        for enc, rel in matched[:5]:
            hits.append((reason, path, rel, enc))

    for reason, path, rel, enc in hits[:100]:
        print(f"{reason} | local={path} | encrypted_rel={rel} | encrypted={enc}")
    print(f"hits={len(hits)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
