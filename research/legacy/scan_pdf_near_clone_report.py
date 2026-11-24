from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import bisect
import csv
import os
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, _project_path('research/legacy'))
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as r


ROOTS = [Path(_case_value('ae6d6877603b6a945206')), Path(_case_value('4ad553a2014833d3f789'))]
REPORT = (
    Path(_case_value('c2cb6ef3d173e2cf36a2'))
    / "_technical_reports"
    / "scan_pdf_near_clone_candidates.csv"
)
DOC_TS_RE = re.compile(r"doc\d{6}(20\d{12})", re.IGNORECASE)
PDF_DATE_RE = re.compile(rb"D:(20\d{12})")


def original_rel(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(r.SRC_ROOT)
    return Path(str(rel)[: -len(r.EXT)])


def parse_name_ts(name: str) -> datetime | None:
    m = DOC_TS_RE.search(name)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), "%Y%m%d%H%M%S")
    except ValueError:
        return None


def pdf_dates(path: Path) -> set[datetime]:
    try:
        data = path.read_bytes()
    except OSError:
        return set()
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-16384:]:
        return set()
    out: set[datetime] = set()
    sample = data[:2_000_000] + data[-200_000:]
    for raw in PDF_DATE_RE.findall(sample):
        try:
            out.add(datetime.strptime(raw.decode("ascii"), "%Y%m%d%H%M%S"))
        except ValueError:
            pass
    return out


def is_candidate_path(path: Path, scan_out: Path) -> bool:
    s = str(path).lower()
    if not path.is_file() or path.suffix.lower() != ".pdf":
        return False
    if s.endswith(".xzg9vrelb"):
        return False
    blocked = [
        str(r.SRC_ROOT / "SCAN").lower(),
        str(scan_out).lower(),
        str(Path(r.DST) / "_technical_reports").lower(),
    ]
    return not any(s.startswith(b) for b in blocked)


def main() -> int:
    os.environ["RECOVER_FOLDER"] = "SCAN"
    groups, _, _ = lr.scan_source(r.SRC_ROOT / "SCAN", [r.EXT], r.SCAN_EXTS, True, 1, r.MAX_SIZE_BYTES, workers=1)

    def is_rec(item: lr.EncryptedFile) -> bool:
        out = r.output_path_for(item)
        return out.exists() and out.stat().st_size > 0 and r.validate_recovered(out, "pdf")

    targets = [
        item for batch in groups.values() for item in batch
        if r.infer_ext(original_rel(item).name) == "pdf" and not is_rec(item) and parse_name_ts(original_rel(item).name)
    ]

    by_second: dict[int, list[Path]] = defaultdict(list)
    scan_out = r.DST / "SCAN"
    seen = set()
    for root in ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*.pdf"):
            if not is_candidate_path(path, scan_out):
                continue
            key = str(path).lower()
            if key in seen:
                continue
            seen.add(key)
            for dt in pdf_dates(path):
                by_second[int(dt.timestamp())].append(path)

    seconds = sorted(by_second)
    windows = [0, 1, 2, 5, 10, 30, 60, 120, 300, 600]
    counts = {w: 0 for w in windows}
    unique_counts = {w: 0 for w in windows}
    rows = []
    for item in targets:
        rel = original_rel(item)
        ts = int(parse_name_ts(rel.name).timestamp())
        best_delta = None
        best_paths: list[Path] = []
        for w in windows:
            lo = bisect.bisect_left(seconds, ts - w)
            hi = bisect.bisect_right(seconds, ts + w)
            paths = []
            for sec in seconds[lo:hi]:
                paths.extend(by_second[sec])
            dedup = sorted({str(p): p for p in paths}.values(), key=lambda p: str(p).lower())
            if dedup:
                counts[w] += 1
            if len(dedup) == 1:
                unique_counts[w] += 1
            if best_delta is None and dedup:
                nearest = min(abs(sec - ts) for sec in seconds[lo:hi])
                best_delta = nearest
                best_paths = dedup[:5]
        rows.append({
            "target": str(rel),
            "target_ts": datetime.fromtimestamp(ts).isoformat(sep=" "),
            "best_delta_sec": "" if best_delta is None else str(best_delta),
            "sample_sources": " | ".join(str(p) for p in best_paths),
        })

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["target", "target_ts", "best_delta_sec", "sample_sources"], delimiter=";")
        writer.writeheader()
        writer.writerows(rows)
    print(f"targets_with_doc_ts={len(targets)} candidate_pdfs={len(seen)} date_seconds={len(seconds)}")
    for w in windows:
        print(f"window=+/-{w:3d}s any={counts[w]} unique={unique_counts[w]}")
    print(f"REPORT {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
