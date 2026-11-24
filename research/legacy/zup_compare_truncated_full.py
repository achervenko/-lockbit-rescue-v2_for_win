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
import hashlib


TRUNC = Path(_case_value('3ad29af15411aaf877ae'))
FULL = Path(_case_value('f4560f9e5b634626d7ec'))


def hash_prefix(path: Path, length: int) -> str:
    h = hashlib.sha256()
    remaining = length
    with path.open("rb") as f:
        while remaining:
            chunk = f.read(min(16 * 1024 * 1024, remaining))
            if not chunk:
                break
            h.update(chunk)
            remaining -= len(chunk)
    return h.hexdigest()


def first_diff(a: Path, b: Path, limit: int) -> int | None:
    pos = 0
    with a.open("rb") as fa, b.open("rb") as fb:
        while pos < limit:
            da = fa.read(min(8 * 1024 * 1024, limit - pos))
            db = fb.read(len(da))
            if da != db:
                for i, (x, y) in enumerate(zip(da, db)):
                    if x != y:
                        return pos + i
                return pos + min(len(da), len(db))
            pos += len(da)
    return None


def main() -> int:
    n = TRUNC.stat().st_size
    print(f"trunc_size={n}")
    print(f"full_size={FULL.stat().st_size}")
    print(f"trunc_sha256={hash_prefix(TRUNC, n)}")
    print(f"full_prefix_sha256={hash_prefix(FULL, n)}")
    diff = first_diff(TRUNC, FULL, n)
    print(f"first_diff={diff if diff is not None else 'none'}")
    if diff is not None:
        with TRUNC.open("rb") as fa, FULL.open("rb") as fb:
            fa.seek(max(0, diff - 32))
            fb.seek(max(0, diff - 32))
            print(f"trunc_context={fa.read(96).hex()}")
            print(f"full_context ={fb.read(96).hex()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
