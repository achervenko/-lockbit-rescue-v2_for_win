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
import math
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
KEK = _case_value('334d517b17c31441017e')


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def sparse_ranges(ks: dict[int, int]) -> str:
    if not ks:
        return ""
    out = []
    start = prev = sorted(ks)[0]
    for off in sorted(ks)[1:]:
        if off == prev + 1:
            prev = off
            continue
        out.append(f"{start}-{prev}" if start != prev else str(start))
        start = prev = off
    out.append(f"{start}-{prev}" if start != prev else str(start))
    return ";".join(out)


def entropy(values: list[int]) -> float:
    if not values:
        return 0.0
    c = Counter(values)
    n = len(values)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def build_initial_ks(files: list[lr.EncryptedFile]) -> tuple[dict[int, int], dict[str, int]]:
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump oracle ks")
    ks = {i: b for i, b in enumerate(base)}
    stats = {"oracle_coverage": oracle.coverage, "base_len": len(base)}
    n_learned, n_conflicts, n_sources = rdt.learn_name_len_metadata(ks, files)
    s_learned, s_conflicts, s_sources = rdt.learn_stable_metadata_profiles(ks, files)
    stats.update(
        {
            "name_len_learned": n_learned,
            "name_len_conflicts": n_conflicts,
            "name_len_sources": n_sources,
            "stable_learned": s_learned,
            "stable_conflicts": s_conflicts,
            "stable_sources": s_sources,
        }
    )
    return ks, stats


def exact_pair_exists(item: lr.EncryptedFile) -> bool:
    out = output_path_for(item)
    if not out.exists() or not out.is_file():
        return False
    try:
        _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
    except Exception:
        return False
    return out.stat().st_size == body_end


def decode_metadata(item: lr.EncryptedFile, ks: dict[int, int]) -> str:
    base = item.coverage
    try:
        _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    except Exception:
        return "read_error"
    if not all(base + i in ks for i in range(18)):
        return "metadata_unknown"
    dec = bytes(fei_ct[base + i] ^ ks[base + i] for i in range(18))
    name_len = int.from_bytes(dec[0:2], "little")
    skipped = int.from_bytes(dec[2:10], "little")
    before = int.from_bytes(dec[10:14], "little")
    after = int.from_bytes(dec[14:18], "little")
    sane = name_len == item.coverage and skipped % 0x20000 == 0 and 0 <= before <= 4096 and 0 <= after <= 4096
    return f"name_len={name_len} skipped={hex(skipped)} before={before} after={after} sane={sane}"


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    files = groups.get(KEK)
    if not files:
        raise RuntimeError(f"KEK {KEK} not found")

    ks, init_stats = build_initial_ks(files)
    before_cov = rdt.contiguous(ks)
    pair_rows: list[dict[str, str]] = []
    recovered_feks: list[bytes] = []
    learned_rounds = []

    # Iterate because recovered FEKs from easier known pairs can extend the
    # shared FEI keystream and unlock slightly harder known pairs.
    seen_fek_items: set[str] = set()
    for round_idx in range(1, 8):
        round_learned = 0
        round_feks = 0
        for item in sorted(files, key=lambda f: (f.fei_len, f.original_name.lower())):
            if item.path in seen_fek_items or not exact_pair_exists(item):
                continue
            fei_len, _, _, _, _ = lr.read_fei_ciphertext(Path(item.path))
            fek_start = fei_len - 64
            missing = [off for off in range(fek_start, fei_len) if off not in ks]
            fek_hex = rdt.recover_fek_from_known_pair(item, ks)
            if not fek_hex:
                continue
            learned = rdt.learn_fek(ks, item, fek_hex)
            seen_fek_items.add(item.path)
            recovered_feks.append(bytes.fromhex(fek_hex))
            round_learned += learned
            round_feks += 1
        learned_rounds.append((round_idx, round_feks, round_learned, rdt.contiguous(ks), len(ks)))
        if round_learned == 0:
            break

    # Per-file status after iterative learning.
    for item in sorted(files, key=lambda f: (f.fei_len, f.original_name.lower())):
        out = output_path_for(item)
        pair = exact_pair_exists(item)
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        fek_start = fei_len - 64
        missing = [off for off in range(fek_start, fei_len) if off not in ks]
        target_tail = [off for off in range(108, 114) if off in range(fek_start, fei_len)]
        pair_rows.append(
            {
                "original_name": item.original_name,
                "pair_exists": str(pair),
                "output_exists": str(out.exists()),
                "body_size": str(body_end),
                "fei_len": str(fei_len),
                "coverage_name": str(item.coverage),
                "fek_start": str(fek_start),
                "missing_fek_count_after_learning": str(len(missing)),
                "missing_fek_offsets_after_learning": ",".join(map(str, missing)),
                "touches_108_113": ",".join(map(str, target_tail)),
                "metadata": decode_metadata(item, ks),
                "encrypted": item.path,
                "output": str(out),
            }
        )

    # Bias/pattern check for recovered FEK bytes.
    bias_rows = []
    for pos in range(64):
        vals = [fek[pos] for fek in recovered_feks if len(fek) == 64]
        c = Counter(vals)
        common = c.most_common(5)
        bias_rows.append(
            {
                "fek_pos": str(pos),
                "samples": str(len(vals)),
                "unique": str(len(c)),
                "entropy": f"{entropy(vals):.4f}",
                "top_values": ";".join(f"{v:02x}:{n}" for v, n in common),
            }
        )

    summary = {
        "scanned": scanned,
        "skipped": skipped,
        "kek": KEK,
        "total_files": len(files),
        "exact_pairs": sum(1 for item in files if exact_pair_exists(item)),
        "initial_contiguous_cov": before_cov,
        "final_contiguous_cov": rdt.contiguous(ks),
        "sparse_known_ranges": sparse_ranges(ks),
        "recovered_feks": len(recovered_feks),
        **init_stats,
    }

    paths = {
        "summary": REPORTS / "reconstruct_fei_4f_summary.csv",
        "files": REPORTS / "reconstruct_fei_4f_files.csv",
        "fek_bias": REPORTS / "reconstruct_fei_4f_fek_bias.csv",
        "rounds": REPORTS / "reconstruct_fei_4f_learning_rounds.csv",
    }
    with paths["summary"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(summary.keys()))
        writer.writeheader()
        writer.writerow(summary)
    with paths["files"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(pair_rows[0].keys()))
        writer.writeheader()
        writer.writerows(pair_rows)
    with paths["fek_bias"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(bias_rows[0].keys()))
        writer.writeheader()
        writer.writerows(bias_rows)
    with paths["rounds"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["round", "new_feks", "new_ks_bytes", "contiguous_cov", "sparse_count"])
        writer.writeheader()
        for row in learned_rounds:
            writer.writerow(
                {
                    "round": row[0],
                    "new_feks": row[1],
                    "new_ks_bytes": row[2],
                    "contiguous_cov": row[3],
                    "sparse_count": row[4],
                }
            )

    print("SUMMARY")
    for key, val in summary.items():
        print(f"{key}={val}")
    print("ROUNDS")
    for row in learned_rounds:
        print(f"round={row[0]} new_feks={row[1]} new_ks={row[2]} cov={row[3]} sparse={row[4]}")
    print("TARGET_OFFSETS_108_113")
    for off in range(108, 114):
        print(f"ks[{off}]={'known' if off in ks else 'unknown'}")
    for name, path in paths.items():
        print(f"{name}={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
