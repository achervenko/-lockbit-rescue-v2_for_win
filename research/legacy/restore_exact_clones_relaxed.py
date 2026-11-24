from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import csv
import hashlib
import os
import shutil
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr

FOLDER = os.environ.get("RECOVER_FOLDER", "ЗАКУПКИ")
ENC_ROOT = Path(_case_value('f6af7da1ad90629ee69b')) / FOLDER
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2')) / FOLDER
SEARCH_ROOTS = [
    Path(_case_value('c2cb6ef3d173e2cf36a2')),
    Path(_case_value('f4e5e33bf20cc2d98993')),
    Path(_case_value('4ad553a2014833d3f789')),
]
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
EXT = ".xzg9VRelb"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_index() -> dict[tuple[str, int], list[Path]]:
    idx: dict[tuple[str, int], list[Path]] = defaultdict(list)
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.name.endswith(EXT):
                continue
            if "_technical_reports" in p.parts:
                continue
            try:
                idx[(p.name.lower(), p.stat().st_size)].append(p)
            except OSError:
                pass
    return idx


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    idx = build_index()
    rows = []
    restored = 0
    ambiguous = 0
    rejected_self = 0
    for enc in ENC_ROOT.rglob("*"):
        if not enc.is_file() or not enc.name.endswith(EXT):
            continue
        rel = Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])
        out = OUT_ROOT / rel
        if out.exists():
            continue
        try:
            _, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
        except Exception as exc:
            rows.append({"status": "READ_ERROR", "rel_path": str(rel), "detail": repr(exc), "source": ""})
            continue
        candidates = [p for p in idx.get((rel.name.lower(), body_end), []) if p.resolve() != out.resolve()]
        if not candidates:
            continue
        by_hash: dict[str, list[Path]] = defaultdict(list)
        for p in candidates:
            try:
                by_hash[sha256(p)].append(p)
            except OSError:
                continue
        if not by_hash:
            continue
        if len(by_hash) > 1:
            ambiguous += 1
            rows.append({"status": "AMBIGUOUS", "rel_path": str(rel), "detail": str(len(by_hash)), "source": "; ".join(str(v[0]) for v in by_hash.values())})
            continue
        source = next(iter(by_hash.values()))[0]
        if source.resolve() == out.resolve():
            rejected_self += 1
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, out)
        restored += 1
        rows.append({"status": "RESTORED_EXACT_CLONE", "rel_path": str(rel), "detail": f"size={body_end}", "source": str(source)})
        print(f"RESTORED {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')} <- {str(source).encode('unicode_escape', errors='backslashreplace').decode('ascii')}", flush=True)

    report = REPORTS / f"{FOLDER}_exact_clone_relaxed_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["status", "rel_path", "detail", "source"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"folder={FOLDER}")
    print(f"restored={restored}")
    print(f"ambiguous={ambiguous}")
    print(f"rejected_self={rejected_self}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
