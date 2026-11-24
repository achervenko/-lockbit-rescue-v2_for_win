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
RANSOM_EXT = ".xzg9VRelb"

MEDIA_EXTS = {"jpg", "jpeg", "jfif", "png", "webp", "mp4", "mov", "m4v", "dav", "lrv", "thm"}


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(RANSOM_EXT)])


def original_ext(name: str) -> str:
    if name.endswith(".partial"):
        parts = name.split(".")
        for part in reversed(parts[:-1]):
            if part:
                return part.lower()
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def file_size_bucket(size: int) -> str:
    mib = size / 1024 / 1024
    if mib < 1:
        return "<1MiB"
    if mib < 5:
        return "1-5MiB"
    if mib < 20:
        return "5-20MiB"
    if mib < 100:
        return "20-100MiB"
    return ">=100MiB"


def merge_dumped_names(files: list[lr.EncryptedFile]) -> tuple[dict[int, int], int, int, int]:
    oracle = max(files, key=lambda f: f.coverage)
    ks: dict[int, int] = {}
    dumps = 0
    conflicts = 0
    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        try:
            more = rdt.run_dump_ks(item)
        except Exception:
            continue
        if more is None:
            continue
        dumps += 1
        for off, val in enumerate(more):
            old = ks.get(off)
            if old is not None and old != val:
                conflicts += 1
                continue
            ks[off] = val
    learned, meta_conflicts, _ = rdt.learn_name_len_metadata(ks, files)
    return ks, dumps, conflicts + meta_conflicts, learned


def decode_metadata(item: lr.EncryptedFile, ks: dict[int, int]) -> tuple[int, int, int, int] | None:
    off = item.coverage
    if not all(i in ks for i in range(off, off + 18)):
        return None
    try:
        _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    except Exception:
        return None
    plain = bytes(fei_ct[i] ^ ks[i] for i in range(off, off + 18))
    name_len = int.from_bytes(plain[0:2], "little")
    skipped = int.from_bytes(plain[2:10], "little")
    before = int.from_bytes(plain[10:14], "little")
    after = int.from_bytes(plain[14:18], "little")
    sane = (
        name_len == item.coverage
        and 0 < skipped <= 64 * 1024 * 1024 * 1024
        and skipped % 0x20000 == 0
        and 0 <= before <= 4096
        and 0 <= after <= 4096
    )
    if not sane:
        return None
    return name_len, skipped, before, after


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(SRC_ROOT, [RANSOM_EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    rows: list[dict[str, object]] = []
    profile_counter: Counter[tuple[str, str, int, int, int]] = Counter()
    group_counter: dict[str, Counter[tuple[int, int, int]]] = defaultdict(Counter)

    for kek, files in sorted(groups.items()):
        if not any(output_path_for(item).exists() for item in files):
            continue
        ks, dumps, conflicts, meta_len_learned = merge_dumped_names(files)
        decoded = 0
        for item in files:
            out = output_path_for(item)
            if not out.exists():
                continue
            meta = decode_metadata(item, ks)
            if meta is None:
                continue
            decoded += 1
            name_len, skipped_bytes, before, after = meta
            enc_path = Path(item.path)
            ext = original_ext(item.original_name)
            size = enc_path.stat().st_size
            row = {
                "kek": kek,
                "ext": ext,
                "size_bucket": file_size_bucket(size),
                "encrypted_size": size,
                "fei_len": item.fei_len,
                "coverage": item.coverage,
                "name_len": name_len,
                "skipped_hex": hex(skipped_bytes),
                "before": before,
                "after": after,
                "path": str(enc_path),
            }
            rows.append(row)
            profile_counter[(ext, file_size_bucket(size), skipped_bytes, before, after)] += 1
            group_counter[kek][(skipped_bytes, before, after)] += 1
        print(
            f"group={kek} files={len(files)} dumps={dumps} conflicts={conflicts} "
            f"meta_len_learned={meta_len_learned} decoded_recovered_meta={decoded} cov={rdt.contiguous(ks)}",
            flush=True,
        )

    profile_rows = []
    for (ext, bucket, skipped_bytes, before, after), count in profile_counter.most_common():
        profile_rows.append({
            "ext": ext,
            "size_bucket": bucket,
            "count": count,
            "skipped_hex": hex(skipped_bytes),
            "before": before,
            "after": after,
        })

    group_rows = []
    for kek, counter in group_counter.items():
        for (skipped_bytes, before, after), count in counter.most_common():
            group_rows.append({
                "kek": kek,
                "count": count,
                "skipped_hex": hex(skipped_bytes),
                "before": before,
                "after": after,
            })

    out_rows = REPORTS / "metadata_profiles_recovered_rows.csv"
    out_profiles = REPORTS / "metadata_profiles_by_ext_size.csv"
    out_groups = REPORTS / "metadata_profiles_by_kek.csv"
    for path, data in ((out_rows, rows), (out_profiles, profile_rows), (out_groups, group_rows)):
        if not data:
            continue
        with path.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(data[0].keys()))
            writer.writeheader()
            writer.writerows(data)
        print(f"wrote={path}")
    print(f"scanned={scanned} skipped={skipped} decoded_rows={len(rows)} profiles={len(profile_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
