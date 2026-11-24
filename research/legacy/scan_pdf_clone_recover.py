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
import re
import shutil
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

sys.path.insert(0, _project_path('research/legacy'))
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as r

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


ROOTS = [
    Path(part)
    for part in os.environ.get(
        "SCAN_CLONE_ROOTS",
        _case_value('7d27be9e9fe2ffa8604a'),
    ).split(";")
    if part.strip()
]
REPORT = (
    Path(_case_value('c2cb6ef3d173e2cf36a2'))
    / "_technical_reports"
    / "scan_pdf_clone_recover.csv"
)
DOC_TS_RE = re.compile(r"doc\d{6}(20\d{12})", re.IGNORECASE)
PDF_DATE_RE = re.compile(rb"D:(20\d{12})")
NEAR_SECONDS = int(os.environ.get("SCAN_CLONE_NEAR_SECONDS", "0"))


def body_size(item: lr.EncryptedFile) -> int:
    return item.size - item.fei_len - 256 - 32


def original_rel(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(r.SRC_ROOT)
    return Path(str(rel)[: -len(r.EXT)])


def is_recovered(item: lr.EncryptedFile) -> bool:
    out = r.output_path_for(item)
    return out.exists() and out.stat().st_size > 0 and r.validate_recovered(out, "pdf")


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
    dates: set[datetime] = set()
    for raw in PDF_DATE_RE.findall(data[:2_000_000] + data[-200_000:]):
        try:
            dates.add(datetime.strptime(raw.decode("ascii"), "%Y%m%d%H%M%S"))
        except ValueError:
            pass
    return dates


def sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def is_candidate_path(path: Path, scan_out: Path) -> bool:
    s = str(path).lower()
    if not path.is_file() or path.suffix.lower() != ".pdf":
        return False
    if ".xz" in s or s.endswith(".xzg9vrelb"):
        return False
    blocked = [
        str(r.SRC_ROOT / "SCAN").lower(),
        str(scan_out).lower(),
        str(Path(r.DST) / "_technical_reports").lower(),
    ]
    return not any(s.startswith(b) for b in blocked)


def main() -> int:
    os.environ["RECOVER_FOLDER"] = "SCAN"
    src = r.SRC_ROOT / "SCAN"
    dst = r.DST / "SCAN"
    groups, _, _ = lr.scan_source(src, [r.EXT], r.SCAN_EXTS, True, 1, r.MAX_SIZE_BYTES, workers=1)
    targets = [
        item
        for batch in groups.values()
        for item in batch
        if r.infer_ext(original_rel(item).name) == "pdf" and not is_recovered(item)
    ]

    by_name_size: dict[tuple[str, int], list[Path]] = defaultdict(list)
    by_date: dict[datetime, list[Path]] = defaultdict(list)
    seen: set[str] = set()
    scan_out = r.DST / "SCAN"
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
            try:
                size = path.stat().st_size
            except OSError:
                continue
            by_name_size[(path.name.lower(), size)].append(path)
            for dt in pdf_dates(path):
                by_date[dt].append(path)

    REPORT.parent.mkdir(parents=True, exist_ok=True)
    copied = 0
    rows: list[dict[str, str]] = []
    for item in sorted(targets, key=lambda f: str(original_rel(f)).lower()):
        rel = original_rel(item)
        out = r.output_path_for(item)
        bsize = body_size(item)
        method = ""
        source: Path | None = None

        exact = by_name_size.get((rel.name.lower(), bsize), [])
        if len(exact) == 1:
            source = exact[0]
            method = "EXACT_NAME_AND_SIZE"
        else:
            ts = parse_name_ts(rel.name)
            if ts:
                hits = by_date.get(ts, [])
                unique_hashes: dict[str, Path] = {}
                for hit in hits:
                    try:
                        unique_hashes.setdefault(sha1(hit), hit)
                    except OSError:
                        pass
                if len(unique_hashes) == 1:
                    source = next(iter(unique_hashes.values()))
                    method = "PDF_CREATIONDATE_EXACT_UNIQUE"
                elif NEAR_SECONDS > 0:
                    near: list[tuple[int, Path]] = []
                    for dt, paths in by_date.items():
                        delta = abs(int((dt - ts).total_seconds()))
                        if delta <= NEAR_SECONDS:
                            for path in paths:
                                near.append((delta, path))
                    unique_paths = {str(path).lower(): (delta, path) for delta, path in near}
                    if len(unique_paths) == 1:
                        delta, path = next(iter(unique_paths.values()))
                        source = path
                        method = f"PDF_CREATIONDATE_NEAR_UNIQUE_{delta}s"

        if source is None:
            rows.append(
                {
                    "status": "MISS",
                    "target": str(rel),
                    "body_size": str(bsize),
                    "method": "",
                    "source": "",
                    "source_size": "",
                }
            )
            continue

        out.parent.mkdir(parents=True, exist_ok=True)
        if not out.exists():
            shutil.copy2(source, out)
            copied += 1
        rows.append(
            {
                "status": "COPIED",
                "target": str(rel),
                "body_size": str(bsize),
                "method": method,
                "source": str(source),
                "source_size": str(source.stat().st_size),
            }
        )

    with REPORT.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=["status", "target", "body_size", "method", "source", "source_size"],
            delimiter=";",
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"targets={len(targets)} copied={copied} report={REPORT}")
    print(f"candidate_pdfs={len(seen)} date_keys={len(by_date)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
