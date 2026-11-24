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
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path

FOLDER = "ЗАКУПКИ"
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
ANALYSIS = REPORTS / f"{FOLDER}_remaining_deep_analysis.csv"
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2')) / FOLDER
SEARCH_ROOTS = [
    Path(_case_value('c2cb6ef3d173e2cf36a2')),
    Path(_case_value('f4e5e33bf20cc2d98993')),
    Path(_case_value('4ad553a2014833d3f789')),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def norm(s: str) -> str:
    return "".join(ch.lower() for ch in s if ch.isalnum())


def main() -> int:
    rows = list(csv.DictReader(ANALYSIS.open(encoding="utf-8-sig")))
    docs = [r for r in rows if r["ext"] not in {"jpg", "mp4"}]
    all_plain: list[Path] = []
    by_size: dict[int, list[Path]] = defaultdict(list)
    by_name: dict[str, list[Path]] = defaultdict(list)
    for root in SEARCH_ROOTS:
        if not root.exists():
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.name.endswith(".xzg9VRelb"):
                continue
            if "_technical_reports" in p.parts:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            all_plain.append(p)
            by_size[size].append(p)
            by_name[p.name.lower()].append(p)

    out_rows = []
    for r in sorted(docs, key=lambda x: int(x["gap"])):
        rel = Path(r["rel_path"])
        size = int(r["size"])
        exact_name = [p for p in by_name.get(rel.name.lower(), []) if p.stat().st_size == size and p.resolve() != (OUT_ROOT / rel).resolve()]
        exact_size = [p for p in by_size.get(size, []) if p.resolve() != (OUT_ROOT / rel).resolve()]
        fuzzy = []
        target_norm = norm(rel.stem)
        for p in exact_size[:5000]:
            score = SequenceMatcher(None, target_norm, norm(p.stem)).ratio()
            if score >= 0.70:
                fuzzy.append((score, p))
        exact_hashes = defaultdict(list)
        for p in exact_name:
            try:
                exact_hashes[sha256(p)].append(p)
            except OSError:
                pass
        out_rows.append(
            {
                "rel_path": str(rel),
                "ext": r["ext"],
                "size": size,
                "gap": r["gap"],
                "kek": r["kek"],
                "exact_name_size_count": len(exact_name),
                "exact_name_size_hashes": len(exact_hashes),
                "exact_name_size_sources": "\n".join(str(v[0]) for v in exact_hashes.values()),
                "same_size_count": len(exact_size),
                "fuzzy_same_size": "\n".join(f"{score:.3f} {p}" for score, p in sorted(fuzzy, reverse=True)[:10]),
            }
        )
        print(f"{rel} gap={r['gap']} exact_name_size={len(exact_name)} hashes={len(exact_hashes)} same_size={len(exact_size)} fuzzy={len(fuzzy)}")
    report = REPORTS / f"{FOLDER}_doc_clone_candidates.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()) if out_rows else ["rel_path"])
        writer.writeheader()
        writer.writerows(out_rows)
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
