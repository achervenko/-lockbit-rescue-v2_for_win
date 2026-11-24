from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


from pathlib import Path
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


SRC = Path(_case_value('f6af7da1ad90629ee69b'))
DST = Path(_case_value('c2cb6ef3d173e2cf36a2'))
RANSOM_EXT = ".xzg9VRelb"


def main() -> int:
    rows = []
    scanned = 0
    for path in SRC.rglob(f"*{RANSOM_EXT}"):
        scanned += 1
        try:
            fei_len, _, _, _, kek = lr.read_fei_ciphertext(path)
        except Exception:
            continue
        if fei_len < 1000:
            continue
        rel = path.relative_to(SRC)
        out = DST / Path(str(rel)[: -len(RANSOM_EXT)])
        rows.append((fei_len, path.stat().st_size, out.exists(), lr.kek_fingerprint(kek), path))
    print(f"scanned={scanned} large_fei={len(rows)}")
    for fei_len, size, ok, kek, path in sorted(rows, key=lambda r: (-r[0], -r[1]))[:200]:
        print(f"{fei_len}\t{size}\t{'RECOVERED' if ok else 'missing'}\t{kek}\t{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
