#!/usr/bin/env python3
"""Iterative encrypted-only/known-pair-assisted recovery for the local sample set.

This is intentionally narrow: it does not touch encrypted sources, does not call
stream-reuse.exe, and only accepts files that pass strict post-decrypt validation.
"""

from __future__ import annotations

import csv
import os
import shutil
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import lockbit_rescue_v2 as lr


SOURCE = Path(os.environ.get("RECOVER_SOURCE", "encrypted"))
OUT = Path(os.environ.get("RECOVER_OUTPUT", "output"))
REPORT = OUT / "iterative_report.txt"
MANIFEST = OUT / "iterative_manifest.csv"
RANSOM_EXT = ".xzg9VRelb"
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000
MAX_BRUTE_STEP = 4


def parse_tool_output(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def dump_name_keystream(tool: Path, item: lr.EncryptedFile) -> bytes:
    arg_name = "hex:" + item.original_name.encode("utf-8").hex()
    result = subprocess.run(
        [str(tool), "--dump-ks", item.path, arg_name],
        capture_output=True,
        text=True,
        timeout=120,
    )
    parsed = parse_tool_output(result.stdout)
    if result.returncode != 0 or parsed.get("STATUS") != "OK_DUMP":
        raise RuntimeError(f"dump-ks failed for {item.path}: {result.stderr}")
    return bytes.fromhex(parsed["KS"])


def merge_byte(ks: dict[int, int], conflicts: list[str], offset: int, value: int, source: str) -> bool:
    old = ks.get(offset)
    if old is not None and old != value:
        conflicts.append(f"offset={offset} old={old:02x} new={value:02x} source={source}")
        return False
    ks[offset] = value
    return True


def contiguous_len(ks: dict[int, int]) -> int:
    i = 0
    while i in ks:
        i += 1
    return i


def gap_counts(files: list[lr.EncryptedFile], coverage: int) -> Counter:
    c: Counter = Counter()
    for f in files:
        gap = max(0, f.fei_len - coverage)
        c[">4" if gap > 4 else str(gap)] += 1
    return c


def ks_ext_hex(ks: dict[int, int], base: int, coverage: int) -> str:
    return bytes(ks[i] for i in range(base, coverage)).hex()


def learn_fek_keystream(ks: dict[int, int], conflicts: list[str], item: lr.EncryptedFile, fek_hex: str) -> int:
    fek = bytes.fromhex(fek_hex)
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    key_offset = fei_len - 64
    learned = 0
    for i, b in enumerate(fek):
        off = key_offset + i
        val = fei_ct[off] ^ b
        before = off in ks
        if merge_byte(ks, conflicts, off, val, f"FEK:{item.original_name}") and not before:
            learned += 1
    return learned


def main() -> int:
    os.environ["PATH"] = r"C:\msys64\ucrt64\bin;" + os.environ.get("PATH", "")
    repo = Path(__file__).resolve().parent
    brute = repo / "brute-extend.exe"
    direct = repo / "direct-decrypt.exe"

    OUT.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(
        SOURCE, [RANSOM_EXT], lr.DEFAULT_COMMON_EXTS, False,
        lr.DEFAULT_MIN_SIZE, lr.DEFAULT_MAX_SIZE, workers=1,
    )
    batch = lr.build_batches(groups, RANSOM_EXT)[0]
    files = sorted(batch.files, key=lambda f: (f.fei_len, f.original_name.lower()))
    oracle = max(files, key=lambda f: f.coverage)
    base_coverage = oracle.coverage

    ks: dict[int, int] = {}
    conflicts: list[str] = []
    for item in files:
        try:
            name_ks = dump_name_keystream(brute, item)
        except Exception as exc:
            conflicts.append(f"dump failed: {item.path}: {exc}")
            continue
        for off, val in enumerate(name_ks):
            merge_byte(ks, conflicts, off, val, f"name:{item.original_name}")

    # Metadata seed validated by the supplied known pair and by target checks:
    # [compressed_name_size:2][skipped_bytes:8][before:4][after:4]
    fei_len, _, _, oracle_fei, _ = lr.read_fei_ciphertext(Path(oracle.path))
    metadata_plain = (
        base_coverage.to_bytes(2, "little")
        + SKIPPED.to_bytes(8, "little")
        + BEFORE.to_bytes(4, "little")
        + AFTER.to_bytes(4, "little")
    )
    for i, plain in enumerate(metadata_plain):
        off = base_coverage + i
        merge_byte(ks, conflicts, off, oracle_fei[off] ^ plain, "metadata_seed")

    recovered: dict[str, str] = {}
    manifest_rows: list[dict[str, str]] = []
    report_lines: list[str] = []

    pass_no = 0
    while True:
        pass_no += 1
        coverage_before = contiguous_len(ks)
        candidates = [
            f for f in files
            if f.path not in recovered
            and lr.get_magic_for_extension(f.original_name.rsplit(".", 1)[-1].lower())
            and 0 <= max(0, f.fei_len - coverage_before) <= MAX_BRUTE_STEP
        ]
        if not candidates:
            break

        new_files = 0
        new_bytes = 0
        report_lines.append(f"PASS {pass_no}")
        report_lines.append(f"coverage before: {coverage_before}")
        report_lines.append(f"gap distribution before: {dict(gap_counts([f for f in files if f.path not in recovered], coverage_before))}")

        progressed = False
        for item in candidates:
            if item.path in recovered:
                continue
            coverage_now = contiguous_len(ks)
            gap = max(0, item.fei_len - coverage_now)
            if gap > MAX_BRUTE_STEP:
                continue

            ext = item.original_name.rsplit(".", 1)[-1].lower()
            magic = lr.get_magic_for_extension(ext)
            result = lr.brute_extend_target(
                brute, Path(item.path), Path(oracle.path), oracle.original_name,
                magic, gap, BEFORE, AFTER, hex(SKIPPED),
                ks_ext_hex(ks, base_coverage, coverage_now),
                timeout=900 if gap >= 3 else 180,
            )
            if not result or result.get("STATUS") not in ("OK_NOBRUTE", "OK_BRUTE"):
                continue

            fek = lr.hex_clean(result.get("FEK", ""))
            if len(fek) != 128:
                continue

            with tempfile.TemporaryDirectory(prefix="iter_recover_") as td:
                tmp_out = Path(td) / "decrypted"
                if not lr.direct_decrypt_file(direct, Path(item.path), tmp_out, fek, BEFORE, AFTER, hex(SKIPPED)):
                    continue
                if not lr.validate_decryption_with_magic(tmp_out, ext):
                    continue
                group_dir = OUT / f"group_{item.kek_fingerprint}"
                group_dir.mkdir(parents=True, exist_ok=True)
                final = group_dir / item.original_name
                shutil.copy2(tmp_out, final)

            method = "PHASE1_DIRECT" if gap == 0 else f"PHASE2_BRUTE_{gap}"
            if coverage_before > base_coverage:
                method = method + "+ORACLE_CHAIN"
            recovered[item.path] = str(final)
            manifest_rows.append({
                "encrypted_path": item.path,
                "recovered_path": str(final),
                "filename": item.original_name,
                "fei_len": str(item.fei_len),
                "gap_at_recovery": str(gap),
                "method": method,
            })
            new_files += 1
            learned = learn_fek_keystream(ks, conflicts, item, fek)
            new_bytes += learned
            progressed = True
            report_lines.append(f"  recovered: {item.original_name} | fei={item.fei_len} | gap={gap} | method={method} | learned={learned}")

        coverage_after = contiguous_len(ks)
        remaining = [f for f in files if f.path not in recovered]
        report_lines.append(f"new files recovered: {new_files}")
        report_lines.append(f"new keystream bytes learned: {new_bytes}")
        report_lines.append(f"coverage after: {coverage_after}")
        report_lines.append(f"remaining files: {len(remaining)}")
        report_lines.append(f"remaining gap distribution: {dict(gap_counts(remaining, coverage_after))}")
        report_lines.append("")

        if not progressed or coverage_after == coverage_before and new_files == 0:
            break

    with MANIFEST.open("w", newline="", encoding="utf-8-sig") as fh:
        fieldnames = ["encrypted_path", "recovered_path", "filename", "fei_len", "gap_at_recovery", "method"]
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(manifest_rows)

    final_coverage = contiguous_len(ks)
    remaining = [f for f in files if f.path not in recovered]
    report_lines.append("FINAL")
    report_lines.append(f"recovered files: {len(recovered)}")
    report_lines.append(f"max coverage: {final_coverage}")
    report_lines.append(f"remaining gap distribution: {dict(gap_counts(remaining, final_coverage))}")
    report_lines.append(f"conflicts: {len(conflicts)}")
    report_lines.extend(f"  CONFLICT {c}" for c in conflicts[:50])
    REPORT.write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print("\n".join(report_lines))
    print(f"manifest: {MANIFEST}")
    print(f"report: {REPORT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
