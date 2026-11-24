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
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
FOLDER = os.environ.get("RECOVER_FOLDER", "СКЛАД")
TARGET_ROOT = SRC_ROOT / FOLDER
PACKER = Path(_project_path('research/legacy/aplib_name_pack.exe'))
EXT = ".xzg9VRelb"


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def pack_names(names: list[str], mode: str = "") -> list[tuple[bytes, int] | None]:
    args = ["hex:" + name.encode("utf-8").hex() for name in names]
    cmd = [str(PACKER), "--batch"]
    if mode:
        cmd.append(mode)
    try:
        result = subprocess.run(
            cmd,
            input="\n".join(args) + "\n",
            capture_output=True,
            text=True,
            timeout=max(30, len(names) // 100 + 30),
        )
    except Exception:
        return [None for _ in names]
    out: list[tuple[bytes, int] | None] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or parts[0] != "OK":
            out.append(None)
            continue
        try:
            out.append((bytes.fromhex(parts[3]), int(parts[2])))
        except ValueError:
            out.append(None)
    if len(out) < len(names):
        out.extend([None] * (len(names) - len(out)))
    return out[: len(names)]


def merge_group_name_ks(files: list[lr.EncryptedFile], mode: str) -> tuple[dict[int, int], int, int, int, Counter]:
    ks: dict[int, int] = {}
    conflicts = 0
    packed_ok = 0
    packed_fail = 0
    length_delta = Counter()
    packed_results = pack_names([item.original_name for item in files], mode)
    for item, packed in zip(files, packed_results):
        if packed is None:
            packed_fail += 1
            continue
        blob, filename_size = packed
        length_delta[len(blob) - item.coverage] += 1
        if len(blob) != item.coverage:
            packed_fail += 1
            continue
        try:
            _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            packed_fail += 1
            continue
        for off, plain in enumerate(blob):
            val = fei_ct[off] ^ plain
            old = ks.get(off)
            if old is not None and old != val:
                conflicts += 1
                continue
            ks[off] = val
        packed_ok += 1
    return ks, packed_ok, packed_fail, conflicts, length_delta


def contiguous(ks: dict[int, int]) -> int:
    i = 0
    while i in ks:
        i += 1
    return i


def validate_metadata(files: list[lr.EncryptedFile], ks: dict[int, int]) -> tuple[int, int, int]:
    checks = 0
    ok = 0
    bad = 0
    for item in files:
        plain = rdt.stable_metadata_plaintext(item)
        if plain is None:
            plain = int(item.coverage).to_bytes(2, "little")
        base = item.coverage
        if not all(base + i in ks for i in range(len(plain))):
            continue
        try:
            _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        got = bytes(fei_ct[base + i] ^ ks[base + i] for i in range(len(plain)))
        checks += 1
        if got == plain:
            ok += 1
        else:
            bad += 1
    return checks, ok, bad


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(
        TARGET_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    rows = []
    best_files = []
    for kek, files in sorted(groups.items()):
        files = sorted(files, key=lambda f: (f.fei_len, f.original_name.lower()))
        mode_results = []
        for mode in ("", "workmem-final"):
            ks, packed_ok, packed_fail, conflicts, length_delta = merge_group_name_ks(files, mode)
            checks, meta_ok, meta_bad = validate_metadata(files, ks)
            mode_results.append((mode or "workmem-zero", ks, packed_ok, packed_fail, conflicts, checks, meta_ok, meta_bad, length_delta))

        # Choose the mode with fewer conflicts and more metadata confirmations.
        chosen = sorted(mode_results, key=lambda r: (r[4], -r[6], -contiguous(r[1])))[0]
        mode, ks, packed_ok, packed_fail, conflicts, checks, meta_ok, meta_bad, length_delta = chosen

        inferred_ks = dict(ks)
        meta_learned, meta_conflicts, _ = rdt.learn_name_len_metadata(inferred_ks, files)
        stable_learned, stable_conflicts, _ = rdt.learn_stable_metadata_profiles(inferred_ks, files)

        remaining = [it for it in files if not output_path_for(it).exists()]
        closest = sorted(remaining, key=lambda it: (max(0, it.fei_len - contiguous(inferred_ks)), -Path(it.path).stat().st_size))
        for item in closest[:10]:
            best_files.append(
                {
                    "kek": kek,
                    "coverage_after_aplib_metadata": contiguous(inferred_ks),
                    "fei_len": item.fei_len,
                    "gap_to_full_fei": max(0, item.fei_len - contiguous(inferred_ks)),
                    "ext": rdt.infer_ext(item.original_name),
                    "path": str(Path(item.path)),
                }
            )
        rows.append(
            {
                "kek": kek,
                "total": len(files),
                "recovered": sum(1 for it in files if output_path_for(it).exists()),
                "remaining": len(remaining),
                "chosen_pack_mode": mode,
                "packed_ok": packed_ok,
                "packed_fail": packed_fail,
                "name_conflicts": conflicts,
                "generated_name_coverage": contiguous(ks),
                "metadata_checks": checks,
                "metadata_ok": meta_ok,
                "metadata_bad": meta_bad,
                "coverage_after_aplib_metadata": contiguous(inferred_ks),
                "metadata_inference_learned": meta_learned + stable_learned,
                "metadata_inference_conflicts": meta_conflicts + stable_conflicts,
                "extra_name_bytes_possible": 0,
                "length_delta_distribution": ";".join(f"{k}:{v}" for k, v in sorted(length_delta.items())),
            }
        )

    rows.sort(key=lambda r: (-int(r["remaining"]), int(r["name_conflicts"])))
    best_files.sort(key=lambda r: (int(r["gap_to_full_fei"]), -int(r["fei_len"])))
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in FOLDER.lower())
    groups_csv = REPORTS / f"aplib_filename_oracle_validation_{safe}.csv"
    best_csv = REPORTS / f"aplib_filename_oracle_best_remaining_{safe}.csv"
    with groups_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["status"])
        w.writeheader()
        w.writerows(rows)
    with best_csv.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(best_files[0].keys()) if best_files else ["status"])
        w.writeheader()
        w.writerows(best_files)

    print(f"folder={FOLDER} scanned={scanned} skipped={skipped} groups={len(groups)}")
    print(f"wrote={groups_csv}")
    print(f"wrote={best_csv}")
    print("TOP_APLIB_GROUPS")
    for row in rows[:16]:
        print(
            f"{row['kek']} rem={row['remaining']} mode={row['chosen_pack_mode']} "
            f"packed_ok={row['packed_ok']} conflicts={row['name_conflicts']} "
            f"meta_ok={row['metadata_ok']}/{row['metadata_checks']} meta_bad={row['metadata_bad']} "
            f"gen_cov={row['generated_name_coverage']} cov_meta={row['coverage_after_aplib_metadata']} "
            f"meta_conf={row['metadata_inference_conflicts']} len_delta={row['length_delta_distribution']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
