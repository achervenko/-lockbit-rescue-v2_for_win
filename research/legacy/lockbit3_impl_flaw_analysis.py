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
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
RANSOM_EXT = ".xzg9VRelb"

FEI_OVERHEAD = 82
FEK_LEN = 64
VIDEO_EXTS = {"mp4", "mov", "m4v", "webm"}


def original_name(enc: Path) -> str:
    name = enc.name
    return name[: -len(RANSOM_EXT)] if name.endswith(RANSOM_EXT) else name


def original_ext(enc: Path) -> str:
    name = original_name(enc)
    if name.endswith(".partial"):
        parts = name.split(".")
        for part in reversed(parts[:-1]):
            if part:
                return part.lower()
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(RANSOM_EXT)])


def sha256_prefix(path: Path, n: int = 4096) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        h.update(f.read(n))
    return h.hexdigest()


def body_stream_digest(enc: Path, out: Path, n: int = 4096) -> tuple[str, int] | None:
    try:
        fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
        take = min(n, body_end, out.stat().st_size)
        if take < 64:
            return None
        with enc.open("rb") as ef, out.open("rb") as of:
            stream = bytes(a ^ b for a, b in zip(ef.read(take), of.read(take)))
        nonzero = sum(1 for b in stream if b)
        if nonzero == 0:
            return None
        return hashlib.sha256(stream).hexdigest(), nonzero
    except Exception:
        return None


def scan() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for enc in SRC_ROOT.rglob(f"*{RANSOM_EXT}"):
        try:
            fei_len, fei_off, body_end, fei_ct, kek = lr.read_fei_ciphertext(enc)
        except Exception as exc:
            rows.append({
                "valid": False,
                "encrypted_path": str(enc),
                "error": repr(exc),
            })
            continue

        out = output_path_for(enc)
        recovered = out.exists() and out.is_file() and out.stat().st_size > 0
        ext = original_ext(enc)
        coverage = max(0, fei_len - FEI_OVERHEAD)
        fek_start = fei_len - FEK_LEN
        gap_from_best_possible_name = max(0, fei_len - coverage)
        # Real recoverability uses batch coverage, filled later.
        rows.append({
            "valid": True,
            "folder": enc.relative_to(SRC_ROOT).parts[0] if enc.parent != SRC_ROOT else "<root>",
            "encrypted_path": str(enc),
            "output_path": str(out) if recovered else "",
            "filename": original_name(enc),
            "ext": ext,
            "encrypted_size": enc.stat().st_size,
            "recovered_size": out.stat().st_size if recovered else 0,
            "recovered": recovered,
            "fei_len": fei_len,
            "fei_offset": fei_off,
            "body_end": body_end,
            "coverage_from_own_filename": coverage,
            "fek_start": fek_start,
            "name_to_fek_gap": max(0, fek_start - coverage),
            "kek_fingerprint": lr.kek_fingerprint(kek),
            "fei_sha256_16": hashlib.sha256(fei_ct).hexdigest()[:16],
            "kek_sha256_16": hashlib.sha256(kek).hexdigest()[:16],
            "enc_prefix_sha256_16": sha256_prefix(enc)[:16],
            "dec_prefix_sha256_16": sha256_prefix(out)[:16] if recovered else "",
            "is_video": ext in VIDEO_EXTS,
        })
    return rows


def enrich_batch_stats(rows: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    by_kek: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row.get("valid"):
            by_kek[str(row["kek_fingerprint"])].append(row)

    summary: dict[str, dict[str, object]] = {}
    for kek, items in by_kek.items():
        max_coverage = max(int(r["coverage_from_own_filename"]) for r in items)
        recovered_count = sum(1 for r in items if r["recovered"])
        total_size = sum(int(r["encrypted_size"]) for r in items)
        recovered_size = sum(int(r["encrypted_size"]) for r in items if r["recovered"])
        ext_counter = Counter(str(r["ext"]) for r in items)
        folder_counter = Counter(str(r["folder"]) for r in items)
        close = Counter()
        for row in items:
            gap = max(0, int(row["fei_len"]) - max_coverage)
            row["batch_max_coverage"] = max_coverage
            row["gap_to_batch_coverage"] = gap
            if gap <= 4:
                close[f"gap_{gap}"] += 1
        summary[kek] = {
            "kek_fingerprint": kek,
            "file_count": len(items),
            "recovered_count": recovered_count,
            "remaining_count": len(items) - recovered_count,
            "recovered_pct": recovered_count / len(items) * 100,
            "total_gb": total_size / 1024**3,
            "recovered_gb": recovered_size / 1024**3,
            "recovered_volume_pct": (recovered_size / total_size * 100) if total_size else 0,
            "min_fei_len": min(int(r["fei_len"]) for r in items),
            "max_fei_len": max(int(r["fei_len"]) for r in items),
            "max_coverage": max_coverage,
            "close_gap_counts": dict(close),
            "top_ext": ";".join(f"{k}:{v}" for k, v in ext_counter.most_common(8)),
            "folders": ";".join(k for k, _ in folder_counter.most_common(8)),
        }
    return summary


def folder_summary(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    by_folder: dict[str, list[dict[str, object]]] = defaultdict(list)
    for row in rows:
        if row.get("valid"):
            by_folder[str(row["folder"])].append(row)
    out = []
    for folder, items in sorted(by_folder.items()):
        total = len(items)
        ok = sum(1 for r in items if r["recovered"])
        size = sum(int(r["encrypted_size"]) for r in items)
        ok_size = sum(int(r["encrypted_size"]) for r in items if r["recovered"])
        out.append({
            "folder": folder,
            "total_files": total,
            "recovered_files": ok,
            "remaining_files": total - ok,
            "recovered_pct": ok / total * 100,
            "total_gb": size / 1024**3,
            "recovered_gb": ok_size / 1024**3,
            "recovered_volume_pct": (ok_size / size * 100) if size else 0,
            "kek_groups": len({str(r["kek_fingerprint"]) for r in items}),
        })
    return out


def chunking_from_repaired_video_manifest() -> list[dict[str, object]]:
    path = REPORTS / "video_repair_manifest_latest.csv"
    if not path.exists():
        return []
    rows = []
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        for row in csv.DictReader(fh):
            if row.get("status") == "REPAIRED":
                rows.append(row)
    return rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    with path.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    rows = scan()
    batch = enrich_batch_stats(rows)
    folders = folder_summary(rows)

    valid_rows = [r for r in rows if r.get("valid")]
    write_csv(REPORTS / "lockbit3_impl_file_inventory.csv", valid_rows)
    write_csv(REPORTS / "lockbit3_impl_kek_groups.csv", list(batch.values()))
    write_csv(REPORTS / "lockbit3_impl_folder_summary.csv", folders)

    stream_groups: dict[str, list[dict[str, object]]] = defaultdict(list)
    sampled = 0
    for row in valid_rows:
        if not row["recovered"]:
            continue
        enc = Path(str(row["encrypted_path"]))
        out = Path(str(row["output_path"]))
        digest = body_stream_digest(enc, out)
        if not digest:
            continue
        sampled += 1
        d, nonzero = digest
        stream_groups[d].append(row | {"stream_nonzero": nonzero})
    dup_streams = {k: v for k, v in stream_groups.items() if len(v) > 1}
    cross_kek_streams = {
        k: v for k, v in dup_streams.items()
        if len({str(r["kek_fingerprint"]) for r in v}) > 1
    }

    chunk_rows = chunking_from_repaired_video_manifest()
    chunk_counter = Counter(
        (row.get("before", ""), row.get("after", ""), row.get("skipped", ""))
        for row in chunk_rows
    )

    total = len(valid_rows)
    recovered = sum(1 for r in valid_rows if r["recovered"])
    total_size = sum(int(r["encrypted_size"]) for r in valid_rows)
    recovered_size = sum(int(r["encrypted_size"]) for r in valid_rows if r["recovered"])
    close_remaining = Counter()
    for row in valid_rows:
        if row["recovered"]:
            continue
        gap = int(row.get("gap_to_batch_coverage", 999999))
        if gap <= 16:
            close_remaining[f"gap_{gap}"] += 1
        else:
            close_remaining["gap_gt_16"] += 1

    top_remaining_batches = sorted(
        batch.values(),
        key=lambda b: (int(b["remaining_count"]), float(b["total_gb"])),
        reverse=True,
    )[:20]

    md = REPORTS / "lockbit3_impl_flaw_analysis.md"
    with md.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# LockBit 3.0 Implementation-Flaw Analysis\n\n")
        f.write("## Scope\n\n")
        f.write(f"- Encrypted root: `{SRC_ROOT}`\n")
        f.write(f"- Recovered root: `{DST_ROOT}`\n")
        f.write(f"- Valid encrypted files analyzed: {total}\n")
        f.write(f"- Recovered files available as known plaintext: {recovered}\n")
        f.write(f"- Recovered volume: {recovered_size / 1024**3:.2f} / {total_size / 1024**3:.2f} GB ({recovered_size / total_size * 100:.2f}%)\n\n")

        f.write("## Confirmed Implementation Weaknesses\n\n")
        f.write("1. **Batch-level FEI keystream reuse by KEK fingerprint.** Files sharing a KEK reuse the FEI stream, so known plaintext from one FEI offsets can decrypt matching offsets in other files from the same batch.\n")
        f.write("2. **Predictable FEI plaintext from filenames.** FEI begins with the aPLib-compressed UTF-16LE original filename. Because the encrypted filename still reveals the original name before `.xzg9VRelb`, every file leaks a prefix of FEI keystream.\n")
        f.write("3. **FEK stored inside the same FEI stream.** The last 64 FEI bytes are the file encryption key. If batch FEI coverage reaches `fei_len`, the FEK is recovered without brute force.\n")
        f.write("4. **Small-gap brute force is practical.** When batch coverage misses only 1-4 FEI bytes, magic-byte validation plus strict file validators can recover additional FEKs.\n")
        f.write("5. **Per-file intermittent encryption parameters are plaintext FEI metadata.** The 18 bytes after compressed filename encode filename length, skipped bytes, before chunk count, and after chunk count. Video analysis proved these are not global constants.\n")
        f.write("6. **Known original/encrypted pairs are extremely valuable.** They validate FEK/body stream and can recover missing FEI bytes or reject false pairs.\n\n")

        f.write("## Important Correction Found During This Analysis\n\n")
        f.write("Earlier assumptions that all files use `before=3`, `after=3`, `skipped=0x520000` are false. Repaired videos showed multiple real chunking profiles:\n\n")
        for (before, after, skipped), count in chunk_counter.most_common():
            f.write(f"- before={before}, after={after}, skipped={skipped}: {count} repaired video(s)\n")
        f.write("\nThis explains MP4 files that opened but had visual/audio artifacts: FEK was correct, but body chunking parameters were wrong.\n\n")

        f.write("## Corpus Summary\n\n")
        f.write("| Folder | Files | Recovered | Remaining | % files | GB | Recovered GB | % volume | KEK groups |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
        for row in folders:
            f.write(
                f"| {row['folder']} | {row['total_files']} | {row['recovered_files']} | {row['remaining_files']} "
                f"| {row['recovered_pct']:.2f}% | {row['total_gb']:.2f} | {row['recovered_gb']:.2f} "
                f"| {row['recovered_volume_pct']:.2f}% | {row['kek_groups']} |\n"
            )

        f.write("\n## Remaining Gap Distribution\n\n")
        for gap, count in sorted(close_remaining.items(), key=lambda kv: int(kv[0].split('_')[1]) if kv[0].startswith('gap_') and kv[0] != 'gap_gt_16' else 999):
            f.write(f"- {gap}: {count}\n")

        f.write("\n## Body Keystream Reuse Check\n\n")
        f.write(f"- Recovered body streams sampled: {sampled}\n")
        f.write(f"- Duplicate 4KB body-stream groups: {len(dup_streams)}\n")
        f.write(f"- Cross-KEK duplicate 4KB body-stream groups: {len(cross_kek_streams)}\n")
        if cross_kek_streams:
            f.write("- Cross-KEK body stream reuse exists and should be investigated manually.\n")
        else:
            f.write("- No cross-KEK body stream reuse found in recovered samples; global Salsa/body keystream reuse is not supported by current evidence.\n")

        f.write("\n## Top Remaining KEK Batches\n\n")
        f.write("| KEK | Files | Recovered | Remaining | Max coverage | FEI range | GB | Top extensions | Folders |\n")
        f.write("|---|---:|---:|---:|---:|---:|---:|---|---|\n")
        for b in top_remaining_batches:
            f.write(
                f"| {b['kek_fingerprint']} | {b['file_count']} | {b['recovered_count']} | {b['remaining_count']} "
                f"| {b['max_coverage']} | {b['min_fei_len']}..{b['max_fei_len']} | {b['total_gb']:.2f} "
                f"| {b['top_ext']} | {b['folders']} |\n"
            )

        f.write("\n## Practical Next Steps\n\n")
        f.write("1. Prioritize original/encrypted pairs from high-remaining KEK groups, not random files.\n")
        f.write("2. For video/photo groups, pairs from the same camera/export folder are more useful than unrelated documents.\n")
        f.write("3. Add pair-driven FEI keystream extraction for targets where `gap_to_batch_coverage <= 16`.\n")
        f.write("4. Keep chunking parameters per-file from FEI; never globally force `3/3/0x520000`.\n")
        f.write("5. Keep strict validators. Magic bytes alone caused false positives and visually corrupted MP4 output.\n")

    print(f"wrote {md}")
    print(f"wrote {REPORTS / 'lockbit3_impl_file_inventory.csv'}")
    print(f"wrote {REPORTS / 'lockbit3_impl_kek_groups.csv'}")
    print(f"wrote {REPORTS / 'lockbit3_impl_folder_summary.csv'}")
    print(f"total={total} recovered={recovered} remaining={total-recovered}")
    print(f"body_stream_samples={sampled} dup_streams={len(dup_streams)} cross_kek={len(cross_kek_streams)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
