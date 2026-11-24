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

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


ENC_ROOT = Path(_case_value('60e26aa6c7e364d54ffa'))
OUT_ROOT = Path(_case_value('89ada5c24a22d61a7d60'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
EXT = ".xzg9VRelb"

AUTO_MARKERS = (
    "авто",
    "автотранспорт",
    "лизинг",
    "haval",
    "changan",
    "volkswagen",
    "audi",
    "топливо",
    "осаго",
    "каско",
    "путевой",
)


def is_auto(rel: Path) -> bool:
    low = str(rel).lower()
    return any(marker in low for marker in AUTO_MARKERS)


def out_rel_for(enc_path: Path) -> Path:
    rel = enc_path.relative_to(ENC_ROOT)
    return Path(str(rel)[: -len(EXT)])


def sha1(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_group_keystream(files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle = None
    ks_bytes = None
    for candidate in sorted(files, key=lambda f: f.coverage, reverse=True):
        ks_bytes = rdt.run_dump_ks(candidate)
        if ks_bytes:
            oracle = candidate
            break
    if oracle is None or not ks_bytes:
        return {}
    ks = {off: val for off, val in enumerate(ks_bytes)}
    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        if item.path == oracle.path:
            continue
        more = rdt.run_dump_ks(item)
        if not more:
            continue
        for off, val in enumerate(more):
            old = ks.get(off)
            if old is None:
                ks[off] = val
            elif old != val:
                ks.pop(off, None)
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    for item in sorted(files, key=lambda f: f.fei_len):
        out = rdt.output_path_for(item)
        if not out.exists():
            continue
        fek = rdt.recover_fek_from_known_pair(item, ks)
        if fek:
            rdt.learn_fek(ks, item, fek)
    return ks


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, 64 * 1024**3, workers=1)

    by_path = {}
    group_ks: dict[str, dict[int, int]] = {}
    for kek, files in groups.items():
        for item in files:
            by_path[Path(item.path)] = (kek, item, files)

    enc_files = [p for p in ENC_ROOT.rglob(f"*{EXT}") if is_auto(out_rel_for(p))]
    missing = [p for p in enc_files if not (OUT_ROOT / out_rel_for(p)).exists()]
    existing = [p for p in enc_files if (OUT_ROOT / out_rel_for(p)).exists()]

    recovered_hashes: dict[tuple[int, str], list[Path]] = defaultdict(list)
    recovered_by_name_size: dict[tuple[str, int], list[Path]] = defaultdict(list)
    for enc in existing:
        out = OUT_ROOT / out_rel_for(enc)
        if not out.is_file():
            continue
        size = out.stat().st_size
        recovered_by_name_size[(out.name.lower(), size)].append(out)
        if size <= 64 * 1024 * 1024:
            recovered_hashes[(size, sha1(out))].append(out)

    rows = []
    for enc in sorted(missing, key=lambda p: str(out_rel_for(p)).lower()):
        rel = out_rel_for(enc)
        resolved = by_path.get(enc)
        if resolved is None:
            rows.append(
                {
                    "rel_path": str(rel),
                    "kek": "",
                    "ext": rel.suffix.lower(),
                    "encrypted_size": enc.stat().st_size,
                    "body_size_est": "",
                    "fei_len": "",
                    "coverage": "",
                    "gap": "",
                    "fek_start": "",
                    "missing_fek": "",
                    "recoverability": "NOT_SCANNED_BY_PIPELINE",
                    "same_name_size_recovered": "",
                }
            )
            continue
        kek, item, files = resolved
        if kek not in group_ks:
            group_ks[kek] = build_group_keystream(files)
        ks = group_ks[kek]
        cov = rdt.contiguous(ks)
        fek_start = item.fei_len - 64
        gap = max(0, item.fei_len - cov)
        missing_fek = sum(1 for off in range(fek_start, item.fei_len) if off not in ks)
        out_candidate = OUT_ROOT / rel
        same_name = recovered_by_name_size.get((out_candidate.name.lower(), max(0, enc.stat().st_size - item.fei_len)), [])
        recoverability = "PAIR_NEEDED"
        if missing_fek == 0:
            recoverability = "DIRECT_OR_REPAIR"
        elif gap <= 4:
            recoverability = f"BRUTE_GAP_{gap}"
        elif same_name:
            recoverability = "CHECK_DUPLICATE_NAME_SIZE"
        rows.append(
            {
                "rel_path": str(rel),
                "kek": kek,
                "ext": rel.suffix.lower(),
                "encrypted_size": enc.stat().st_size,
                "body_size_est": max(0, enc.stat().st_size - item.fei_len),
                "fei_len": item.fei_len,
                "coverage": cov,
                "gap": gap,
                "fek_start": fek_start,
                "missing_fek": missing_fek,
                "recoverability": recoverability,
                "same_name_size_recovered": " | ".join(str(p) for p in same_name[:3]),
            }
        )

    report = REPORTS / "exploitation_auto_remaining_analysis.csv"
    with report.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["rel_path"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"auto_encrypted={len(enc_files)} auto_existing={len(existing)} auto_missing={len(missing)}")
    print(f"report={report}")
    print("recoverability:", dict(Counter(r["recoverability"] for r in rows)))
    print("gaps:", dict(sorted(Counter(int(r["gap"]) for r in rows if r["gap"] != "").items())[:30]))
    print("keks:", Counter(r["kek"] for r in rows).most_common(10))
    print("top_direct_or_close:")
    sortable = [r for r in rows if r["gap"] != "" and r["missing_fek"] != ""]
    for r in sorted(sortable, key=lambda x: (int(x["missing_fek"]), int(x["gap"]), int(x["encrypted_size"])))[:30]:
        print(f"{r['recoverability']} gap={r['gap']} miss_fek={r['missing_fek']} fei={r['fei_len']} {r['rel_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
