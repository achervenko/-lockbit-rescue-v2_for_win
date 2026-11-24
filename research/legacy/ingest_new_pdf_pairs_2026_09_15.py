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
import os
import re
import shutil
import sys
from collections import defaultdict
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
PAIR_ROOT = DST_ROOT / "_technical_reports" / "new_pairs_2026-09-15"
REPORTS = DST_ROOT / "_technical_reports"
REPORT = REPORTS / "new_pairs_2026-09-15_ingest_report.csv"


def norm_name(name: str) -> str:
    return name.casefold().replace("ё", "е")


def norm_without_leading_date(name: str) -> str:
    normalized = norm_name(name)
    return re.sub(r"^\d{6}_", "", normalized)


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(rdt.EXT)])


def main() -> int:
    groups, scanned, skipped = lr.scan_source(SRC_ROOT / "СКЛАД", [rdt.EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    by_name: dict[str, list[tuple[str, lr.EncryptedFile, int]]] = defaultdict(list)
    by_tail: dict[str, list[tuple[str, lr.EncryptedFile, int]]] = defaultdict(list)
    for kek, files in groups.items():
        for item in files:
            if rdt.infer_ext(item.original_name).lower() != "pdf":
                continue
            try:
                _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
            except Exception:
                body_end = -1
            by_name[norm_name(item.original_name)].append((kek, item, body_end))
            by_tail[norm_without_leading_date(item.original_name)].append((kek, item, body_end))

    rows: list[dict[str, object]] = []
    copied = 0
    exact = 0
    ambiguous = 0
    no_match = 0
    size_mismatch = 0

    pair_files = sorted(PAIR_ROOT.rglob("*.pdf")) + sorted(PAIR_ROOT.rglob("*.PDF"))
    seen_pairs = set()
    deduped = []
    for p in pair_files:
        key = str(p).casefold()
        if key not in seen_pairs:
            seen_pairs.add(key)
            deduped.append(p)

    for pair in deduped:
        name = pair.name
        psize = pair.stat().st_size
        candidates = by_name.get(norm_name(name), [])
        if not candidates:
            fuzzy_candidates = [
                (kek, item, body_end)
                for kek, item, body_end in by_tail.get(norm_without_leading_date(name), [])
                if body_end == psize
            ]
            if len(fuzzy_candidates) == 1:
                kek, item, body_end = fuzzy_candidates[0]
                out = output_path_for(item)
                out.parent.mkdir(parents=True, exist_ok=True)
                already = out.exists()
                if not already:
                    shutil.copy2(pair, out)
                    copied += 1
                exact += 1
                rows.append(
                    {
                        "status": "FUZZY_DATE_COPIED" if not already else "FUZZY_DATE_ALREADY_EXISTS",
                        "pair": str(pair),
                        "pair_size": psize,
                        "kek": kek,
                        "encrypted": str(item.path),
                        "body_end": body_end,
                        "output": str(out),
                        "note": "same filename after stripping leading YYMMDD_ and exact body size",
                    }
                )
                continue
            no_match += 1
            rows.append(
                {
                    "status": "NO_MATCH",
                    "pair": str(pair),
                    "pair_size": psize,
                    "kek": ";".join(k for k, _, _ in fuzzy_candidates),
                    "encrypted": ";".join(str(item.path) for _, item, _ in fuzzy_candidates[:5]),
                    "body_end": ";".join(str(body_end) for _, _, body_end in fuzzy_candidates[:5]),
                    "output": "",
                    "note": "no encrypted PDF with same original filename; fuzzy date match was not unique/exact",
                }
            )
            continue
        exact_candidates = [(kek, item, body_end) for kek, item, body_end in candidates if body_end == psize]
        if not exact_candidates:
            size_mismatch += 1
            rows.append(
                {
                    "status": "SIZE_MISMATCH",
                    "pair": str(pair),
                    "pair_size": psize,
                    "kek": ";".join(k for k, _, _ in candidates),
                    "encrypted": ";".join(str(item.path) for _, item, _ in candidates[:5]),
                    "body_end": ";".join(str(body_end) for _, _, body_end in candidates[:5]),
                    "output": "",
                    "note": f"name matched {len(candidates)} encrypted file(s), no exact body size",
                }
            )
            continue
        if len(exact_candidates) > 1:
            ambiguous += 1
        for kek, item, body_end in exact_candidates:
            out = output_path_for(item)
            out.parent.mkdir(parents=True, exist_ok=True)
            already = out.exists()
            if not already:
                shutil.copy2(pair, out)
                copied += 1
            exact += 1
            rows.append(
                {
                    "status": "EXACT_COPIED" if not already else "EXACT_ALREADY_EXISTS",
                    "pair": str(pair),
                    "pair_size": psize,
                    "kek": kek,
                    "encrypted": str(item.path),
                    "body_end": body_end,
                    "output": str(out),
                    "note": f"exact candidates={len(exact_candidates)}",
                }
            )

    REPORTS.mkdir(parents=True, exist_ok=True)
    with REPORT.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["status", "pair", "pair_size", "kek", "encrypted", "body_end", "output", "note"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"scanned={scanned} skipped={skipped} pair_files={len(deduped)}")
    print(f"exact_matches={exact} copied_new={copied} ambiguous_names={ambiguous} no_match={no_match} size_mismatch={size_mismatch}")
    print(f"report={REPORT}")
    for row in rows:
        if row["status"].startswith("EXACT"):
            print(f"{row['status']} kek={row['kek']} {Path(str(row['output'])).relative_to(DST_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
