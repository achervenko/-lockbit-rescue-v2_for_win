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
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def out_path(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def folder_name(enc: Path) -> str:
    rel = enc.relative_to(SRC_ROOT)
    return rel.parts[0] if len(rel.parts) > 1 else "<root>"


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
    return ";".join(f"{a}-{b}" if a != b else str(a) for a, b in ranges[:8])


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    max_gap = int(os.environ.get("NEXT_MAX_GAP", "8"))
    all_groups: dict[str, list[lr.EncryptedFile]] = defaultdict(list)
    scanned_total = 0
    skipped_total = 0

    roots = [p for p in SRC_ROOT.iterdir() if p.is_dir()]
    for root in roots:
        try:
            groups, scanned, skipped = lr.scan_source(
                root, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
            )
        except Exception:
            continue
        scanned_total += scanned
        skipped_total += skipped
        for kek, files in groups.items():
            all_groups[kek].extend(files)

    rows = []
    close_rows = []
    for kek, files in all_groups.items():
        recovered = [it for it in files if out_path(Path(it.path)).exists()]
        remaining = [it for it in files if not out_path(Path(it.path)).exists()]
        if not recovered or not remaining:
            continue

        oracle = max(files, key=lambda f: f.coverage)
        ks = {}
        try:
            base = rdt.run_dump_ks(oracle)
        except Exception:
            base = None
        if not base:
            continue
        for i, b in enumerate(base):
            ks[i] = b

        name_learned, name_conflicts, name_sources = rdt.learn_name_len_metadata(ks, files)
        stable_learned, stable_conflicts, stable_sources = rdt.learn_stable_metadata_profiles(ks, files)
        cov = rdt.contiguous(ks)
        dist = Counter(max(0, it.fei_len - cov) for it in remaining)
        rem_bytes = sum(Path(it.path).stat().st_size for it in remaining if Path(it.path).exists())
        folders = Counter(folder_name(Path(it.path)) for it in files)
        rem_exts = Counter(rdt.infer_ext(it.original_name) for it in remaining)

        best_close = sorted(remaining, key=lambda it: (max(0, it.fei_len - cov), -Path(it.path).stat().st_size))
        top_close = []
        close_volume = 0
        for it in best_close:
            gap = max(0, it.fei_len - cov)
            if gap > max_gap:
                break
            size = Path(it.path).stat().st_size
            close_volume += size
            top_close.append((gap, size, rdt.infer_ext(it.original_name), str(Path(it.path))))
            close_rows.append({
                "kek": kek,
                "folder": folder_name(Path(it.path)),
                "gap": gap,
                "fei_len": it.fei_len,
                "coverage": cov,
                "size_gb": size / (1024**3),
                "ext": rdt.infer_ext(it.original_name),
                "path": str(Path(it.path)),
            })

        rows.append({
            "kek": kek,
            "folders": ";".join(k for k, _ in folders.most_common(5)),
            "total": len(files),
            "recovered": len(recovered),
            "remaining": len(remaining),
            "remaining_gb": rem_bytes / (1024**3),
            "coverage": cov,
            "sparse": sparse_ranges(ks),
            "name_learned": name_learned,
            "name_conflicts": name_conflicts,
            "stable_learned": stable_learned,
            "stable_conflicts": stable_conflicts,
            "gap0": dist.get(0, 0),
            "gap1": dist.get(1, 0),
            "gap2": dist.get(2, 0),
            "gap3": dist.get(3, 0),
            "gap4": dist.get(4, 0),
            "gap5": dist.get(5, 0),
            "gap6_8": sum(dist.get(i, 0) for i in range(6, max_gap + 1)),
            "close_count": len(top_close),
            "close_gb": close_volume / (1024**3),
            "top_remaining_exts": ";".join(f"{k}:{v}" for k, v in rem_exts.most_common(8)),
            "best_path": top_close[0][3] if top_close else "",
            "best_gap": top_close[0][0] if top_close else "",
            "best_ext": top_close[0][2] if top_close else "",
            "best_size_gb": top_close[0][1] / (1024**3) if top_close else "",
        })

    rows.sort(key=lambda r: (r["close_gb"], r["gap0"] + r["gap1"] + r["gap2"] + r["gap3"] + r["gap4"], r["remaining_gb"]), reverse=True)
    close_rows.sort(key=lambda r: (r["gap"], -r["size_gb"]))

    groups_csv = REPORTS / "next_recovery_candidate_groups.csv"
    files_csv = REPORTS / "next_recovery_candidate_files.csv"
    with groups_csv.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        if rows:
            w.writeheader()
            w.writerows(rows)
    with files_csv.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(close_rows[0].keys()) if close_rows else [])
        if close_rows:
            w.writeheader()
            w.writerows(close_rows)

    print(f"scanned={scanned_total} skipped={skipped_total} groups={len(all_groups)}")
    print(f"wrote={groups_csv}")
    print(f"wrote={files_csv}")
    print("TOP GROUPS")
    for row in rows[:20]:
        print(
            f"{row['kek']} folders={row['folders']} rec={row['recovered']}/{row['total']} "
            f"rem={row['remaining']} rem_gb={row['remaining_gb']:.2f} cov={row['coverage']} "
            f"close<= {max_gap}: {row['close_count']} files/{row['close_gb']:.2f}GB "
            f"gaps 0:{row['gap0']} 1:{row['gap1']} 2:{row['gap2']} 3:{row['gap3']} "
            f"4:{row['gap4']} 5:{row['gap5']} 6-8:{row['gap6_8']} best_gap={row['best_gap']} "
            f"best={row['best_path']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
