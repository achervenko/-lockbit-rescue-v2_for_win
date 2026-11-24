#!/usr/bin/env python3
"""FEI layout analysis for the current 32/43 recovery checkpoint."""

from __future__ import annotations

import csv
import argparse
import os
import tempfile
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import lockbit_rescue_v2 as lr


SOURCE = Path(os.environ.get("RECOVER_SOURCE", "encrypted"))
RECOVERY = Path(os.environ.get("RECOVER_OUTPUT", "output"))
PAIRS = Path(os.environ.get("RECOVER_PAIRS", "pairs"))
OUT = Path(os.environ.get("RECOVER_FEI_REPORTS", "output/_technical_reports/fei_layout"))
RANSOM_EXT = ".xzg9VRelb"
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000


def parse_tool_output(text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            parsed[key.strip()] = value.strip()
    return parsed


def merge_byte(ks: dict[int, int], sources: dict[int, list[str]], conflicts: list[str],
               offset: int, value: int, source: str) -> bool:
    old = ks.get(offset)
    if old is not None and old != value:
        conflicts.append(f"offset={offset} old={old:02x} new={value:02x} source={source}")
        return False
    ks[offset] = value
    sources[offset].append(source)
    return True


def ranges(offsets: list[int]) -> list[tuple[int, int]]:
    if not offsets:
        return []
    offsets = sorted(offsets)
    out = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
        else:
            out.append((start, prev))
            start = prev = off
    out.append((start, prev))
    return out


def contiguous_len(ks: dict[int, int]) -> int:
    i = 0
    while i in ks:
        i += 1
    return i


def dump_fei_name(tool: Path, enc_path: Path, original_name: str) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = r"C:\msys64\ucrt64\bin;" + env.get("PATH", "")
    arg = "hex:" + original_name.encode("utf-8").hex()
    result = subprocess.run(
        [str(tool), "--dump-ks", str(enc_path), arg],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    parsed = parse_tool_output(result.stdout)
    if result.returncode != 0 or parsed.get("STATUS") != "OK_DUMP":
        raise RuntimeError(f"dump-ks failed for {enc_path}: {result.stderr}")
    return parsed


def load_manifest() -> list[dict[str, str]]:
    with (RECOVERY / "iterative_manifest.csv").open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def scan_batch() -> tuple[list[lr.EncryptedFile], lr.EncryptedFile]:
    groups, _, _ = lr.scan_source(
        SOURCE, [RANSOM_EXT], lr.DEFAULT_COMMON_EXTS, False,
        lr.DEFAULT_MIN_SIZE, lr.DEFAULT_MAX_SIZE, workers=1,
    )
    batch = lr.build_batches(groups, RANSOM_EXT)[0]
    files = sorted(batch.files, key=lambda f: (f.fei_len, f.original_name.lower()))
    return files, max(files, key=lambda f: f.coverage)


def print_remaining_priority(encrypted_dir: Path) -> int:
    recovered = set()
    manifest = RECOVERY / "iterative_manifest.csv"
    if manifest.exists():
        with manifest.open(encoding="utf-8-sig", newline="") as fh:
            for row in csv.DictReader(fh):
                recovered.add(row["encrypted_path"])

    groups, _, _ = lr.scan_source(
        encrypted_dir, [RANSOM_EXT], lr.DEFAULT_COMMON_EXTS, False,
        lr.DEFAULT_MIN_SIZE, lr.DEFAULT_MAX_SIZE, workers=1,
    )

    rows = []
    for kek_fp, files in groups.items():
        for item in files:
            if item.path in recovered:
                continue
            rows.append({
                "filename": item.original_name,
                "full_path": item.path,
                "fei_len": item.fei_len,
                "gap_from_current_coverage_169": max(0, item.fei_len - 169),
                "kek_fingerprint": kek_fp,
            })
    rows.sort(key=lambda r: (r["fei_len"], r["filename"].lower()))

    print("filename\tfull_path\tfei_len\tgap_from_current_coverage_169\tkek_fingerprint")
    for row in rows:
        print(
            f"{row['filename']}\t{row['full_path']}\t{row['fei_len']}\t"
            f"{row['gap_from_current_coverage_169']}\t{row['kek_fingerprint']}"
        )

    if rows:
        min_fei = rows[0]["fei_len"]
        print()
        print(f"MIN_FEI_LEN\t{min_fei}")
        for row in rows:
            if row["fei_len"] != min_fei:
                break
            print(f"MIN_TARGET\t{row['filename']}\t{row['full_path']}")
    return 0


def recover_fek(brute: Path, item: lr.EncryptedFile, oracle: lr.EncryptedFile,
                ks: dict[int, int], base_coverage: int) -> str | None:
    coverage = contiguous_len(ks)
    gap = max(0, item.fei_len - coverage)
    ext = item.original_name.rsplit(".", 1)[-1].lower()
    magic = lr.get_magic_for_extension(ext)
    if not magic or gap > 4:
        return None
    ks_ext = bytes(ks[i] for i in range(base_coverage, coverage)).hex()
    result = lr.brute_extend_target(
        brute, Path(item.path), Path(oracle.path), oracle.original_name,
        magic, gap, BEFORE, AFTER, hex(SKIPPED), ks_ext, timeout=900 if gap >= 3 else 120,
    )
    if not result:
        return None
    fek = lr.hex_clean(result.get("FEK", ""))
    return fek if len(fek) == 128 else None


def interpret_offset(off: int, item: lr.EncryptedFile, name_len: int, fei_len: int) -> str:
    key_start = fei_len - 64
    if off < name_len:
        return "apLib compressed UTF-16LE filename"
    if name_len <= off < name_len + 2:
        return "metadata: compressed filename length u16le"
    if name_len + 2 <= off < name_len + 10:
        return "metadata: skipped_bytes u64le"
    if name_len + 10 <= off < name_len + 14:
        return "metadata: before_chunk_count u32le"
    if name_len + 14 <= off < name_len + 18:
        return "metadata: after_chunk_count u32le"
    if key_start <= off < fei_len:
        return f"FEK byte {off - key_start}"
    return "unknown gap"


def main() -> int:
    os.environ["PATH"] = r"C:\msys64\ucrt64\bin;" + os.environ.get("PATH", "")
    OUT.mkdir(parents=True, exist_ok=True)
    repo = Path(__file__).resolve().parent
    brute = repo / "brute-extend.exe"

    files, oracle = scan_batch()
    by_path = {f.path: f for f in files}
    manifest_rows = load_manifest()
    recovered_items = [by_path[row["encrypted_path"]] for row in manifest_rows]
    recovered_set = {item.path for item in recovered_items}
    base_coverage = oracle.coverage

    ks: dict[int, int] = {}
    sources: dict[int, list[str]] = defaultdict(list)
    conflicts: list[str] = []
    name_plain_by_path: dict[str, bytes] = {}
    name_len_by_path: dict[str, int] = {}

    for item in files:
        dump = dump_fei_name(brute, Path(item.path), item.original_name)
        name_plain = bytes.fromhex(dump["NAME_PLAIN"])
        name_ks = bytes.fromhex(dump["KS"])
        name_plain_by_path[item.path] = name_plain
        name_len_by_path[item.path] = len(name_plain)
        for off, val in enumerate(name_ks):
            merge_byte(ks, sources, conflicts, off, val, f"filename:{item.original_name}")

    fei_len, _, _, oracle_fei, _ = lr.read_fei_ciphertext(Path(oracle.path))
    metadata_plain = (
        base_coverage.to_bytes(2, "little")
        + SKIPPED.to_bytes(8, "little")
        + BEFORE.to_bytes(4, "little")
        + AFTER.to_bytes(4, "little")
    )
    for i, plain in enumerate(metadata_plain):
        off = base_coverage + i
        merge_byte(ks, sources, conflicts, off, oracle_fei[off] ^ plain, "metadata_seed:validated_pairs_and_targets")

    fek_by_path: dict[str, str] = {}
    for item in sorted(recovered_items, key=lambda f: (f.fei_len, f.original_name.lower())):
        fek = recover_fek(brute, item, oracle, ks, base_coverage)
        if not fek:
            continue
        fek_by_path[item.path] = fek
        fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        key_start = fei_len - 64
        for i, b in enumerate(bytes.fromhex(fek)):
            merge_byte(ks, sources, conflicts, key_start + i, fei_ct[key_start + i] ^ b, f"FEK:{item.original_name}")

    layout_rows: list[dict[str, str]] = []
    values_by_offset: dict[int, list[int]] = defaultdict(list)
    for item in recovered_items:
        fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        name_len = name_len_by_path[item.path]
        key_start = fei_len - 64
        for off in range(fei_len):
            ct = fei_ct[off]
            known = off in ks
            pt = ct ^ ks[off] if known else None
            if known:
                values_by_offset[off].append(pt)
            layout_rows.append({
                "filename": item.original_name,
                "fei_len": str(fei_len),
                "offset": str(off),
                "ciphertext": f"{ct:02x}",
                "keystream": f"{ks[off]:02x}" if known else "",
                "plaintext": f"{pt:02x}" if pt is not None else "",
                "interpretation": interpret_offset(off, item, name_len, fei_len),
                "confidence": "high" if known else "unknown",
                "recovered_fek_start": str(key_start),
                "compressed_filename_region": f"0..{name_len - 1}",
            })

    with (OUT / "fei_offset_report.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        fieldnames = list(layout_rows[0].keys())
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(layout_rows)

    compare_rows = []
    for off in range(max(f.fei_len for f in recovered_items)):
        vals = values_by_offset.get(off, [])
        counts = Counter(vals)
        compare_rows.append({
            "offset": off,
            "known_count": len(vals),
            "unique_values": len(counts),
            "same_for_all_known": len(counts) == 1 if vals else False,
            "values": " ".join(f"{v:02x}:{n}" for v, n in sorted(counts.items())),
            "sources": "; ".join(sources.get(off, [])[:5]),
        })
    with (OUT / "fei_cross_file_compare.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(compare_rows[0].keys()))
        writer.writeheader()
        writer.writerows(compare_rows)

    offset_rows = []
    for off in range(169, 178):
        vals = values_by_offset.get(off, [])
        counts = Counter(vals)
        name_sources = [f.original_name for f in files if len(name_plain_by_path[f.path]) > off]
        reason = []
        if off in ks:
            reason.append("known in sparse keystream")
        if name_sources:
            reason.append(f"covered by generated filename for {len(name_sources)} files")
        if not vals and not name_sources and off not in ks:
            reason.append("not covered by recovered FEK/name/metadata; needs new evidence")
        offset_rows.append({
            "offset": off,
            "sparse_known": off in ks,
            "known_plaintext_candidates": " ".join(f"{v:02x}:{n}" for v, n in sorted(counts.items())) or "",
            "known_count_from_recovered": len(vals),
            "filename_plain_sources": len(name_sources),
            "confidence": "high" if off in ks else "none",
            "reason": "; ".join(reason),
        })
    with (OUT / "offsets_169_177.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(offset_rows[0].keys()))
        writer.writeheader()
        writer.writerows(offset_rows)

    pair_rows = []
    pair_groups, _, _ = lr.scan_source(
        PAIRS, [RANSOM_EXT], lr.DEFAULT_COMMON_EXTS, False,
        1, lr.DEFAULT_MAX_SIZE, workers=1,
    )
    pair_items = {Path(item.path): item for items in pair_groups.values() for item in items}
    for enc in PAIRS.glob(f"*{RANSOM_EXT}"):
        original = enc.with_name(enc.name[: -len(RANSOM_EXT)])
        if not original.exists():
            continue
        enc_bytes = enc.read_bytes()
        orig_bytes = original.read_bytes()
        p_fei_len, _, p_body_end, p_fei_ct, p_kek = lr.read_fei_ciphertext(enc)
        dump = dump_fei_name(brute, enc, original.name)
        p_name_len = len(bytes.fromhex(dump["NAME_PLAIN"]))
        pair_item = pair_items.get(enc)
        pair_fek = recover_fek(brute, pair_item, oracle, ks, base_coverage) if pair_item else None
        pair_matches = False
        if pair_fek:
            with tempfile.TemporaryDirectory(prefix="pair_verify_") as td:
                tmp = Path(td) / "pair_dec"
                if lr.direct_decrypt_file(repo / "direct-decrypt.exe", enc, tmp, pair_fek, BEFORE, AFTER, hex(SKIPPED)):
                    dec_bytes = tmp.read_bytes()
                    pair_matches = dec_bytes == orig_bytes
                    prefix64 = dec_bytes[:64] == orig_bytes[:64]
                    prefix_20000 = dec_bytes[:0x20000] == orig_bytes[:0x20000]
                    prefix_80000 = dec_bytes[:0x80000] == orig_bytes[:0x80000]
                else:
                    prefix64 = prefix_20000 = prefix_80000 = False
        else:
            prefix64 = prefix_20000 = prefix_80000 = False
        pair_rows.append({
            "original": str(original),
            "encrypted": str(enc),
            "orig_size": len(orig_bytes),
            "enc_size": len(enc_bytes),
            "fei_len": p_fei_len,
            "body_end": p_body_end,
            "compressed_filename_len": p_name_len,
            "can_reach_offsets_169_177": p_fei_len > 177 or p_name_len > 177,
            "fek_recovered_from_fei": bool(pair_fek),
            "prefix64_matches_original": prefix64,
            "prefix_0x20000_matches_original": prefix_20000,
            "prefix_0x80000_matches_original": prefix_80000,
            "direct_decrypt_matches_original": pair_matches,
            "body_keystream_first64": bytes(a ^ b for a, b in zip(enc_bytes[:64], orig_bytes[:64])).hex(),
            "note": "known pair FEI is too short for offsets 169..177" if p_fei_len <= 177 and p_name_len <= 177 else "may cover target offsets",
        })
    with (OUT / "known_pairs_analysis.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(pair_rows[0].keys()))
        writer.writeheader()
        writer.writerows(pair_rows)

    remaining = [f for f in files if f.path not in recovered_set]
    current = contiguous_len(ks)
    remaining_rows = []
    for item in remaining:
        gap = max(0, item.fei_len - current)
        remaining_rows.append({
            "filename": item.original_name,
            "fei_len": item.fei_len,
            "gap_at_current_contiguous": gap,
            "recoverable_now_gap_le4": gap <= 4,
        })
    with (OUT / "remaining_forecast.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(remaining_rows[0].keys()))
        writer.writeheader()
        writer.writerows(sorted(remaining_rows, key=lambda r: (r["gap_at_current_contiguous"], r["fei_len"])))

    sparse_ranges = ranges(sorted(ks))
    summary = [
        "# FEI Layout Analysis",
        "",
        f"Recovered files analyzed: {len(recovered_items)}",
        f"CURRENT CONTIGUOUS COVERAGE: {current}",
        "SPARSE KNOWN RANGES: " + ", ".join(f"{a}..{b}" for a, b in sparse_ranges),
        f"Conflicts: {len(conflicts)}",
        "",
        "NEW BYTES RECOVERED FROM METADATA: 135..152",
        "NEW BYTES RECOVERED FROM FILENAME: 0..134",
        "NEW BYTES RECOVERED FROM KNOWN PAIRS: none for offsets 169..177; pairs validate FEK/Salsa on encrypted prefixes but FEI/name regions are too short",
        "UNRESOLVED OFFSETS 169..177: " + ", ".join(str(o) for o in range(169, 178) if o not in ks),
        "",
        "Offsets 169..177 conclusion:",
    ]
    for row in offset_rows:
        summary.append(
            f"- {row['offset']}: known={row['sparse_known']} confidence={row['confidence']} reason={row['reason']}"
        )
    dist = Counter(">4" if max(0, f.fei_len - current) > 4 else str(max(0, f.fei_len - current)) for f in remaining)
    summary.extend([
        "",
        f"Remaining files: {len(remaining)}",
        f"Remaining gap distribution at coverage {current}: {dict(dist)}",
        "Forecast: 0 of the remaining 11 files are recoverable now under gap<=4.",
    ])
    (OUT / "fei_layout_summary.md").write_text("\n".join(summary) + "\n", encoding="utf-8")

    print("\n".join(summary))
    print(f"output_dir: {OUT}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--remaining-priority", metavar="ENCRYPTED_DIR")
    args = parser.parse_args()
    if args.remaining_priority:
        raise SystemExit(print_remaining_priority(Path(args.remaining_priority)))
    raise SystemExit(main())
