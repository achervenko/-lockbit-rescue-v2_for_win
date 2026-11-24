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
EXT = ".xzg9VRelb"
PACKER = Path(_project_path('research/legacy/aplib_name_pack.exe'))
FOLDER = os.environ.get("RECOVER_FOLDER", r"archive-2026-09-03_14-15-10\extracted_correct")
TARGET_ROOT = SRC_ROOT / FOLDER


def safe_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in name.lower())


def out_path(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def parse_original_roots() -> list[str]:
    roots: list[str] = []
    for p in TARGET_ROOT.rglob("путь.txt"):
        try:
            text = p.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip().strip('"')
            if len(line) >= 3 and line[1:3] == ":\\":
                roots.append(line.rstrip("\\/"))
    return sorted(set(roots))


def candidate_variants(item: lr.EncryptedFile, original_roots: list[str]) -> dict[str, str]:
    enc = Path(item.path)
    rel_target = enc.relative_to(TARGET_ROOT)
    rel_src = enc.relative_to(SRC_ROOT)
    rel_no_ext = Path(str(rel_target)[: -len(EXT)])
    src_rel_no_ext = Path(str(rel_src)[: -len(EXT)])
    basename = enc.name[: -len(EXT)]
    variants: dict[str, str] = {
        "lr_original_name": item.original_name,
        "basename": basename,
        "rel_target_backslash": str(rel_no_ext),
        "rel_target_slash": str(rel_no_ext).replace("\\", "/"),
        "rel_src_backslash": str(src_rel_no_ext),
        "rel_src_slash": str(src_rel_no_ext).replace("\\", "/"),
    }

    parts = rel_no_ext.parts
    for cut in range(1, min(len(parts), 5)):
        sub = Path(*parts[cut:])
        variants[f"rel_target_cut{cut}_backslash"] = str(sub)
        variants[f"rel_target_cut{cut}_slash"] = str(sub).replace("\\", "/")

    for root in original_roots:
        root_name = Path(root).name.lower()
        for cut in range(0, min(len(parts), 5)):
            sub = Path(*parts[cut:])
            joined = root + "\\" + str(sub)
            variants[f"origroot_cut{cut}_backslash"] = joined
            variants[f"origroot_cut{cut}_slash"] = joined.replace("\\", "/")
            if parts and parts[0].lower().replace("�", "") in root_name:
                joined0 = root + "\\" + str(Path(*parts[1:]))
                variants["origroot_drop_top_backslash"] = joined0
                variants["origroot_drop_top_slash"] = joined0.replace("\\", "/")

    # BagIRA samples sometimes come from archives with mojibake top folders.
    # Also test the known source roots from the path hint against the useful
    # internal subtree only.
    for root in original_roots:
        if "м-11" in root.lower():
            for marker in ("м-11 на печать",):
                if marker in str(rel_no_ext):
                    suffix = str(rel_no_ext).split(marker, 1)[1].lstrip("\\/")
                    base = root + ("\\" + suffix if suffix else "")
                    variants["hint_m11_backslash"] = base
                    variants["hint_m11_slash"] = base.replace("\\", "/")
        if "рсг" in root.lower():
            if "РСГ" in str(rel_no_ext):
                suffix = str(rel_no_ext).split("РСГ", 1)[1].lstrip("\\/")
                base = root + ("\\" + suffix if suffix else "")
                variants["hint_rsg_backslash"] = base
                variants["hint_rsg_slash"] = base.replace("\\", "/")

    return {k: v for k, v in variants.items() if v}


def pack_names(names: list[str], mode: str) -> list[tuple[bytes, int] | None]:
    if not names:
        return []
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
            timeout=max(30, len(names) // 50 + 30),
        )
    except Exception:
        return [None] * len(names)
    rows: list[tuple[bytes, int] | None] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or parts[0] != "OK":
            rows.append(None)
            continue
        try:
            rows.append((bytes.fromhex(parts[3]), int(parts[2])))
        except ValueError:
            rows.append(None)
    if len(rows) < len(names):
        rows.extend([None] * (len(names) - len(rows)))
    return rows[: len(names)]


def contiguous(ks: dict[int, int]) -> int:
    i = 0
    while i in ks:
        i += 1
    return i


def score_variant(files: list[lr.EncryptedFile], variant: str, original_roots: list[str], mode: str) -> dict[str, object]:
    names = [candidate_variants(item, original_roots).get(variant, "") for item in files]
    packed = pack_names(names, mode)
    ks: dict[int, int] = {}
    packed_ok = 0
    packed_fail = 0
    conflicts = 0
    len_delta = Counter()
    samples: list[str] = []

    for item, name, packed_item in zip(files, names, packed):
        if not name or packed_item is None:
            packed_fail += 1
            continue
        blob, _filename_size = packed_item
        len_delta[len(blob) - item.coverage] += 1
        if len(blob) != item.coverage:
            packed_fail += 1
            continue
        try:
            _fei_len, _body_start, _body_end, fei_ct, _kek = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            packed_fail += 1
            continue
        local_conflict = False
        for off, plain in enumerate(blob):
            val = fei_ct[off] ^ plain
            old = ks.get(off)
            if old is not None and old != val:
                conflicts += 1
                local_conflict = True
                continue
            ks[off] = val
        if not local_conflict and len(samples) < 3:
            samples.append(name)
        packed_ok += 1

    meta_ks = dict(ks)
    meta_len_learned, meta_len_conflicts, meta_len_sources = rdt.learn_name_len_metadata(meta_ks, files)
    stable_learned, stable_conflicts, stable_sources = rdt.learn_stable_metadata_profiles(meta_ks, files)
    remaining = [item for item in files if not out_path(item).exists()]
    gaps = Counter(max(0, item.fei_len - contiguous(meta_ks)) for item in remaining)
    return {
        "variant": variant,
        "mode": mode or "default",
        "packed_ok": packed_ok,
        "packed_fail": packed_fail,
        "name_conflicts": conflicts,
        "name_cov": contiguous(ks),
        "cov_after_metadata": contiguous(meta_ks),
        "sparse_known": len(meta_ks),
        "meta_len_sources": meta_len_sources,
        "meta_len_learned": meta_len_learned,
        "meta_len_conflicts": meta_len_conflicts,
        "stable_sources": stable_sources,
        "stable_learned": stable_learned,
        "stable_conflicts": stable_conflicts,
        "gap0_remaining": gaps.get(0, 0),
        "gap1_4_remaining": sum(gaps.get(i, 0) for i in range(1, 5)),
        "gap5_16_remaining": sum(gaps.get(i, 0) for i in range(5, 17)),
        "gap_gt16_remaining": sum(v for k, v in gaps.items() if k > 16),
        "length_delta_distribution": ";".join(f"{k}:{v}" for k, v in sorted(len_delta.items())),
        "sample_candidate": " | ".join(samples),
    }


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(
        TARGET_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    original_roots = parse_original_roots()
    all_rows: list[dict[str, object]] = []
    best_rows: list[dict[str, object]] = []

    for kek, files in sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True):
        files = sorted(files, key=lambda item: (item.fei_len, item.original_name.lower()))
        variant_names = sorted({name for item in files[:50] for name in candidate_variants(item, original_roots)})
        rows = []
        for variant in variant_names:
            for mode in ("", "workmem-final"):
                row = score_variant(files, variant, original_roots, mode)
                row["kek"] = kek
                row["total"] = len(files)
                row["recovered"] = sum(1 for item in files if out_path(item).exists())
                row["remaining"] = sum(1 for item in files if not out_path(item).exists())
                rows.append(row)
        rows.sort(
            key=lambda r: (
                int(r["name_conflicts"]),
                -int(r["packed_ok"]),
                -int(r["cov_after_metadata"]),
                -int(r["sparse_known"]),
            )
        )
        all_rows.extend(rows)
        best_rows.extend(rows[:10])

    all_rows.sort(
        key=lambda r: (
            str(r["kek"]),
            int(r["name_conflicts"]),
            -int(r["packed_ok"]),
            -int(r["cov_after_metadata"]),
        )
    )
    best_rows.sort(key=lambda r: (int(r["name_conflicts"]), -int(r["packed_ok"]), -int(r["cov_after_metadata"])))
    tag = safe_name(FOLDER)
    all_csv = REPORTS / f"bagira_oracle_variants_{tag}.csv"
    best_csv = REPORTS / f"bagira_oracle_variants_best_{tag}.csv"
    fields = [
        "kek", "total", "recovered", "remaining", "variant", "mode",
        "packed_ok", "packed_fail", "name_conflicts", "name_cov",
        "cov_after_metadata", "sparse_known", "meta_len_sources",
        "meta_len_learned", "meta_len_conflicts", "stable_sources",
        "stable_learned", "stable_conflicts", "gap0_remaining",
        "gap1_4_remaining", "gap5_16_remaining", "gap_gt16_remaining",
        "length_delta_distribution", "sample_candidate",
    ]
    for path, rows in ((all_csv, all_rows), (best_csv, best_rows)):
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    print(f"folder={FOLDER}")
    print(f"scanned={scanned} groups={len(groups)} skipped={skipped} original_roots={len(original_roots)}")
    print(f"wrote={all_csv}")
    print(f"wrote={best_csv}")
    print("BEST_VARIANTS")
    for row in best_rows[:20]:
        print(
            f"kek={row['kek']} rem={row['remaining']} variant={row['variant']} mode={row['mode']} "
            f"ok={row['packed_ok']} conflicts={row['name_conflicts']} "
            f"cov={row['cov_after_metadata']} sparse={row['sparse_known']} "
            f"g0={row['gap0_remaining']} g1_4={row['gap1_4_remaining']} "
            f"sample={row['sample_candidate'][:120]}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
