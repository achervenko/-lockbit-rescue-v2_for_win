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
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
SKLAD = SRC_ROOT / "СКЛАД"
EXT = ".xzg9VRelb"


def output_path_for_encrypted(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def load_pair_paths() -> dict[str, str]:
    paired: dict[str, str] = {}
    reports = sorted(REPORTS.glob("sklad_pairs_apply_report*.csv")) + sorted(REPORTS.glob("sklad_fuzzy_pairs_apply_report*.csv"))
    for report in reports:
        with report.open("r", encoding="utf-8-sig", newline="") as f:
            for row in csv.DictReader(f):
                status = row.get("status", "")
                enc = row.get("encrypted", "")
                pair = row.get("pair", "")
                if not enc or not pair:
                    continue
                if status in {"COPIED", "COPIED_PAIR", "COPIED_FUZZY_PAIR", "SKIP_EXISTS"}:
                    paired[str(Path(enc))] = pair
    return paired


def sparse_ranges(ks: dict[int, int]) -> str:
    if not ks:
        return ""
    offs = sorted(ks)
    chunks = []
    start = prev = offs[0]
    for off in offs[1:]:
        if off == prev + 1:
            prev = off
            continue
        chunks.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = off
    chunks.append(f"{start}-{prev}" if start != prev else str(start))
    return ";".join(chunks[:12])


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    paired = load_pair_paths()
    groups, scanned, skipped = lr.scan_source(
        SKLAD, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )

    rows = []
    group_rows = []
    status_counts = Counter()
    possible_now = 0
    paired_items = 0

    for kek, files in sorted(groups.items()):
        oracle = max(files, key=lambda f: f.coverage)
        ks: dict[int, int] = {}
        base = None
        try:
            base = rdt.run_dump_ks(oracle)
        except Exception:
            pass
        if base:
            for i, b in enumerate(base):
                ks[i] = b
        name_learned, name_conflicts, name_sources = rdt.learn_name_len_metadata(ks, files)
        stable_learned, stable_conflicts, stable_sources = rdt.learn_stable_metadata_profiles(ks, files)
        cov = rdt.contiguous(ks)

        recovered = 0
        remaining = 0
        group_possible = 0
        group_paired = 0
        missing_fek_dist = Counter()
        min_missing = None
        min_gap = None

        for item in files:
            enc = Path(item.path)
            out = output_path_for_encrypted(enc)
            if out.exists() and out.is_file() and out.stat().st_size > 0:
                recovered += 1
            else:
                remaining += 1

            if str(enc) not in paired:
                continue

            paired_items += 1
            group_paired += 1
            try:
                fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            except Exception:
                continue
            fek_start = fei_len - 64
            missing = [off for off in range(fek_start, fei_len) if off not in ks]
            missing_count = len(missing)
            gap = max(0, fei_len - cov)
            size_ok = out.exists() and out.is_file() and out.stat().st_size == body_end
            current_oracle_possible = size_ok and missing_count <= 2
            if current_oracle_possible:
                possible_now += 1
                group_possible += 1
            missing_fek_dist[missing_count] += 1
            min_missing = missing_count if min_missing is None else min(min_missing, missing_count)
            min_gap = gap if min_gap is None else min(min_gap, gap)
            status = "CURRENT_PAIR_ORACLE_POSSIBLE" if current_oracle_possible else "PAIR_BODY_ONLY_NOT_ENOUGH"
            status_counts[status] += 1
            rows.append(
                {
                    "kek": kek,
                    "encrypted": str(enc),
                    "output": str(out),
                    "pair": paired[str(enc)],
                    "fei_len": fei_len,
                    "coverage": cov,
                    "gap_from_coverage": gap,
                    "fek_start": fek_start,
                    "missing_fek_bytes": missing_count,
                    "output_size_matches_body": int(size_ok),
                    "current_pair_oracle_possible": int(current_oracle_possible),
                    "status": status,
                }
            )

        group_rows.append(
            {
                "kek": kek,
                "total": len(files),
                "recovered": recovered,
                "remaining": remaining,
                "paired_outputs": group_paired,
                "coverage": cov,
                "sparse_ranges": sparse_ranges(ks),
                "name_sources": name_sources,
                "name_learned": name_learned,
                "name_conflicts": name_conflicts,
                "stable_sources": stable_sources,
                "stable_learned": stable_learned,
                "stable_conflicts": stable_conflicts,
                "pair_oracle_possible_now": group_possible,
                "min_paired_gap": "" if min_gap is None else min_gap,
                "min_paired_missing_fek": "" if min_missing is None else min_missing,
                "missing_fek_distribution": ";".join(f"{k}:{v}" for k, v in sorted(missing_fek_dist.items())),
            }
        )

    rows.sort(key=lambda r: (int(r["current_pair_oracle_possible"]) * -1, int(r["missing_fek_bytes"]), int(r["gap_from_coverage"])))
    group_rows.sort(key=lambda r: (int(r["pair_oracle_possible_now"]) * -1, r["min_paired_missing_fek"] == "", r["min_paired_missing_fek"], -int(r["paired_outputs"]) if r["paired_outputs"] else 0))

    pair_csv = REPORTS / "sklad_pair_oracle_analysis.csv"
    group_csv = REPORTS / "sklad_pair_oracle_groups.csv"
    with pair_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["status"])
        w.writeheader()
        w.writerows(rows)
    with group_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(group_rows[0].keys()) if group_rows else ["status"])
        w.writeheader()
        w.writerows(group_rows)

    print(f"scanned={scanned} skipped={skipped} groups={len(groups)} paired_items={paired_items}")
    print(f"pair_oracle_possible_now={possible_now}")
    print("status_counts=" + ";".join(f"{k}:{v}" for k, v in status_counts.items()))
    print(f"wrote={pair_csv}")
    print(f"wrote={group_csv}")
    print("TOP_GROUPS")
    for row in group_rows[:12]:
        print(
            f"{row['kek']} total={row['total']} rec={row['recovered']} rem={row['remaining']} "
            f"paired={row['paired_outputs']} cov={row['coverage']} possible={row['pair_oracle_possible_now']} "
            f"min_missing_fek={row['min_paired_missing_fek']} dist={row['missing_fek_distribution']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
