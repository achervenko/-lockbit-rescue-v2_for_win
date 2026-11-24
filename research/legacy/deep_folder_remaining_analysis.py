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
import shutil
import sys
from collections import Counter, defaultdict
from pathlib import Path

FOLDER = os.environ.get("RECOVER_FOLDER", "ЗАКУПКИ")
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from salvage_exploitation_auto_tail import validate_bytes


ENC_ROOT = Path(_case_value('f6af7da1ad90629ee69b')) / FOLDER
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2')) / FOLDER
RECOVERED_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
PAIR_ROOT = Path(_case_value('f4e5e33bf20cc2d98993'))
DOWNLOADS = Path(_case_value('4ad553a2014833d3f789'))
REPORTS = RECOVERED_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_plain_index() -> dict[tuple[str, int], list[Path]]:
    roots = [RECOVERED_ROOT, PAIR_ROOT, DOWNLOADS]
    index: dict[tuple[str, int], list[Path]] = defaultdict(list)
    ignored_parts = {"Зашифрованные файлы", "_technical_reports"}
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or path.name.endswith(EXT):
                continue
            if any(part in ignored_parts for part in path.parts):
                continue
            try:
                index[(path.name.lower(), path.stat().st_size)].append(path)
            except OSError:
                continue
    return index


def try_clone_restore(rel: Path, body_size: int, ext: str, out: Path, plain_index: dict[tuple[str, int], list[Path]]) -> tuple[str, str]:
    candidates = plain_index.get((rel.name.lower(), body_size), [])
    if not candidates:
        return "", ""
    by_hash: dict[str, list[Path]] = defaultdict(list)
    for candidate in candidates:
        try:
            by_hash[sha256(candidate)].append(candidate)
        except OSError:
            continue
    if len(by_hash) != 1:
        return f"CLONE_AMBIGUOUS:{len(by_hash)}", ""
    source = next(iter(by_hash.values()))[0]
    try:
        data = source.read_bytes()
    except OSError:
        return "CLONE_READ_ERROR", ""
    ok = True
    if ext in {"pdf", "docx", "xlsx", "pptx", "jpg", "jpeg", "png", "mp4", "mov", "msg", "doc", "rtf"}:
        ok = validate_bytes(data, "." + ext)[0]
    if not ok:
        return "CLONE_REJECTED", str(source)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, out)
    return "CLONE_RESTORED", str(source)


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    plain_index = build_plain_index()
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    ks_by_kek: dict[str, dict[int, int]] = {}
    rows = []
    clone_restored = 0

    for kek, files in sorted(groups.items()):
        for item in sorted(files, key=lambda f: Path(f.path).stat().st_size):
            enc = Path(item.path)
            rel = out_rel_for(enc)
            out = OUT_ROOT / rel
            if out.exists():
                continue
            _, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            ext = rel.suffix.lower().lstrip(".")
            clone_status, clone_source = try_clone_restore(rel, body_end, ext, out, plain_index)
            if clone_status == "CLONE_RESTORED":
                clone_restored += 1

            if kek not in ks_by_kek:
                ks_by_kek[kek] = build_group_keystream(files)
            ks = ks_by_kek[kek]
            cov = rdt.contiguous(ks)
            gap = max(0, item.fei_len - cov)
            has_fek = bool(rdt.derive_fek_from_ks(ks, item)) if gap == 0 else False
            rows.append(
                {
                    "rel_path": str(rel),
                    "size": body_end,
                    "ext": ext,
                    "kek": kek,
                    "fei_len": item.fei_len,
                    "coverage": cov,
                    "gap": gap,
                    "has_fek": has_fek,
                    "clone_status": clone_status,
                    "clone_source": clone_source,
                }
            )

    safe = FOLDER.replace("\\", "_").replace("/", "_")
    report = REPORTS / f"{safe}_remaining_deep_analysis.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = list(rows[0].keys()) if rows else ["rel_path"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"folder={FOLDER}")
    print(f"remaining_rows={len(rows)}")
    print(f"clone_restored={clone_restored}")
    print("gap_dist", Counter(int(row["gap"]) for row in rows).most_common(30))
    print("ext_dist", Counter(row["ext"] or "<none>" for row in rows).most_common(30))
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
