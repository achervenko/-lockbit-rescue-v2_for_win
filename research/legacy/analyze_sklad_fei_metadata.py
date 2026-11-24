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
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
SKLAD = SRC_ROOT / "СКЛАД"
EXT = ".xzg9VRelb"


def out_path(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def sparse_ranges(ks: dict[int, int]) -> str:
    if not ks:
        return ""
    offs = sorted(ks)
    ranges = []
    start = prev = offs[0]
    for off in offs[1:]:
        if off == prev + 1:
            prev = off
            continue
        ranges.append((start, prev))
        start = prev = off
    ranges.append((start, prev))
    return ";".join(f"{a}-{b}" if a != b else str(a) for a, b in ranges[:16])


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(
        SKLAD, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    rows = []
    close_rows = []

    for kek, files in sorted(groups.items()):
        oracle = max(files, key=lambda f: f.coverage)
        ks: dict[int, int] = {}
        base_len = 0
        try:
            base = rdt.run_dump_ks(oracle)
        except Exception:
            base = None
        if base:
            base_len = len(base)
            for i, b in enumerate(base):
                ks[i] = b

        name_learned, name_conflicts, name_sources = rdt.learn_name_len_metadata(ks, files)
        stable_learned, stable_conflicts, stable_sources = rdt.learn_stable_metadata_profiles(ks, files)
        cov = rdt.contiguous(ks)
        remaining = [it for it in files if not out_path(it).exists()]
        recovered = len(files) - len(remaining)
        rem_exts = Counter(rdt.infer_ext(it.original_name) for it in remaining)
        all_exts = Counter(rdt.infer_ext(it.original_name) for it in files)

        gaps_to_fei = Counter(max(0, it.fei_len - cov) for it in remaining)
        gaps_to_fek_start = Counter(max(0, (it.fei_len - 64) - cov) for it in remaining)
        max_name_cov = max(it.coverage for it in files)
        min_rem_fei = min((it.fei_len for it in remaining), default=0)
        min_rem_fek_start = min((it.fei_len - 64 for it in remaining), default=0)
        best = sorted(
            remaining,
            key=lambda it: (max(0, (it.fei_len - 64) - cov), max(0, it.fei_len - cov), -Path(it.path).stat().st_size),
        )
        for it in best[:20]:
            close_rows.append(
                {
                    "kek": kek,
                    "coverage": cov,
                    "fei_len": it.fei_len,
                    "fek_start": it.fei_len - 64,
                    "missing_to_fek_start": max(0, (it.fei_len - 64) - cov),
                    "gap_to_full_fei": max(0, it.fei_len - cov),
                    "ext": rdt.infer_ext(it.original_name),
                    "size": Path(it.path).stat().st_size,
                    "path": str(Path(it.path)),
                }
            )

        fixed_metadata_status = "exhausted"
        if name_conflicts or stable_conflicts:
            fixed_metadata_status = "conflicts_left_untrusted"
        elif cov < max_name_cov + 18:
            fixed_metadata_status = "blocked_by_compressed_filename"

        rows.append(
            {
                "kek": kek,
                "total": len(files),
                "recovered": recovered,
                "remaining": len(remaining),
                "base_ks_len": base_len,
                "coverage_after_metadata": cov,
                "sparse_ranges": sparse_ranges(ks),
                "oracle_name": oracle.original_name,
                "oracle_coverage": oracle.coverage,
                "max_filename_region": max_name_cov,
                "min_remaining_fei_len": min_rem_fei,
                "min_remaining_fek_start": min_rem_fek_start,
                "min_missing_to_fek_start": "" if not best else max(0, (best[0].fei_len - 64) - cov),
                "min_gap_to_full_fei": "" if not best else max(0, best[0].fei_len - cov),
                "gap_full_0": gaps_to_fei.get(0, 0),
                "gap_full_1_4": sum(gaps_to_fei.get(i, 0) for i in range(1, 5)),
                "gap_full_5_8": sum(gaps_to_fei.get(i, 0) for i in range(5, 9)),
                "gap_full_9_16": sum(gaps_to_fei.get(i, 0) for i in range(9, 17)),
                "gap_full_gt16": sum(v for k, v in gaps_to_fei.items() if k > 16),
                "missing_to_fek_start_0": gaps_to_fek_start.get(0, 0),
                "missing_to_fek_start_1_4": sum(gaps_to_fek_start.get(i, 0) for i in range(1, 5)),
                "missing_to_fek_start_5_8": sum(gaps_to_fek_start.get(i, 0) for i in range(5, 9)),
                "missing_to_fek_start_9_16": sum(gaps_to_fek_start.get(i, 0) for i in range(9, 17)),
                "missing_to_fek_start_gt16": sum(v for k, v in gaps_to_fek_start.items() if k > 16),
                "name_sources": name_sources,
                "name_learned": name_learned,
                "name_conflicts": name_conflicts,
                "stable_sources": stable_sources,
                "stable_learned": stable_learned,
                "stable_conflicts": stable_conflicts,
                "fixed_metadata_status": fixed_metadata_status,
                "remaining_exts": ";".join(f"{k}:{v}" for k, v in rem_exts.most_common(8)),
                "all_exts": ";".join(f"{k}:{v}" for k, v in all_exts.most_common(8)),
            }
        )

    rows.sort(key=lambda r: (-int(r["remaining"]), int(r["min_missing_to_fek_start"] or 9999)))
    close_rows.sort(key=lambda r: (int(r["missing_to_fek_start"]), int(r["gap_to_full_fei"]), -int(r["size"])))

    group_csv = REPORTS / "sklad_fei_metadata_groups.csv"
    close_csv = REPORTS / "sklad_fei_metadata_best_files.csv"
    with group_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["status"])
        w.writeheader()
        w.writerows(rows)
    with close_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(close_rows[0].keys()) if close_rows else ["status"])
        w.writeheader()
        w.writerows(close_rows)

    print(f"scanned={scanned} skipped={skipped} groups={len(groups)}")
    print(f"wrote={group_csv}")
    print(f"wrote={close_csv}")
    print("TOP_SKLAD_METADATA_GROUPS")
    for row in rows[:16]:
        print(
            f"{row['kek']} rec={row['recovered']}/{row['total']} rem={row['remaining']} "
            f"cov={row['coverage_after_metadata']} base={row['base_ks_len']} "
            f"min_to_fek={row['min_missing_to_fek_start']} min_full_gap={row['min_gap_to_full_fei']} "
            f"stable_learned={row['stable_learned']} status={row['fixed_metadata_status']} "
            f"exts={row['remaining_exts']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
