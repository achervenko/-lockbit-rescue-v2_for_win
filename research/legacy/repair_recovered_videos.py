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
import shutil
import subprocess
import tempfile
from pathlib import Path

import recover_desktop_tree as r
import lockbit_rescue_v2 as lr


VIDEO_EXTS = {".mp4", ".mov", ".m4v", ".webm"}
FOLDER = "ФОТО ВИДЕО"


def build_batch_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle = max(files, key=lambda f: f.coverage)
    ks: dict[int, int] = {}

    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        more = r.run_dump_ks(item)
        if not more:
            continue
        for off, val in enumerate(more):
            r.merge_ks(ks, off, val)
    return ks


def output_for(item: lr.EncryptedFile) -> Path:
    return r.output_path_for(item)


def video_items(groups: dict[str, list[lr.EncryptedFile]]) -> list[tuple[str, lr.EncryptedFile]]:
    items: list[tuple[str, lr.EncryptedFile]] = []
    for kek, files in groups.items():
        for item in files:
            out = output_for(item)
            if out.exists() and out.suffix.lower() in VIDEO_EXTS:
                items.append((kek, item))
    return sorted(items, key=lambda ki: str(output_for(ki[1])).lower())


def main() -> int:
    r.RECOVER_FOLDER = FOLDER
    r.SRC = r.SRC_ROOT / FOLDER
    r.MAX_GAP = int(os.environ.get("RECOVER_MAX_GAP", str(r.MAX_GAP)))
    r.REPORTS.mkdir(parents=True, exist_ok=True)

    groups, scanned, skipped = lr.scan_source(
        r.SRC, [r.EXT], r.SCAN_EXTS, False, 1, r.MAX_SIZE_BYTES, workers=1
    )
    print(f"SCANNED files={scanned} groups={len(groups)} skipped={skipped}", flush=True)

    ks_by_kek = {kek: build_batch_ks(files) for kek, files in groups.items()}
    rows: list[dict[str, str]] = []
    repaired = failed = 0

    for kek, item in video_items(groups):
        out = output_for(item)
        ks = ks_by_kek[kek]
        fek_hex = r.derive_fek_from_ks(ks, item)
        if not fek_hex:
            rows.append({
                "status": "FAILED",
                "reason": "NO_FEK_FROM_KS",
                "kek": kek,
                "encrypted_path": item.path,
                "output_path": str(out),
                "before": "",
                "after": "",
                "skipped": "",
            })
            failed += 1
            continue

        before, after, skipped_bytes, source = r.chunking_params_for(item, ks)
        if source != "FEI_PARAMS":
            rows.append({
                "status": "FAILED",
                "reason": source,
                "kek": kek,
                "encrypted_path": item.path,
                "output_path": str(out),
                "before": str(before),
                "after": str(after),
                "skipped": hex(skipped_bytes),
            })
            failed += 1
            continue

        with tempfile.TemporaryDirectory(prefix="video_repair_") as td:
            tmp = Path(td) / out.name
            ok = lr.direct_decrypt_file(
                r.REPO / "direct-decrypt.exe",
                Path(item.path),
                tmp,
                fek_hex,
                before,
                after,
                hex(skipped_bytes),
            )
            if not ok or not r.validate_recovered(tmp, r.infer_ext(item.original_name)):
                rows.append({
                    "status": "FAILED",
                    "reason": "DECRYPT_OR_VALIDATE_FAILED",
                    "kek": kek,
                    "encrypted_path": item.path,
                    "output_path": str(out),
                    "before": str(before),
                    "after": str(after),
                    "skipped": hex(skipped_bytes),
                })
                failed += 1
                continue

            backup = out.with_name(out.name + ".bad-chunking.bak")
            if backup.exists():
                backup.unlink()
            out.replace(backup)
            shutil.copy2(tmp, out)
            backup.unlink()

        repaired += 1
        rows.append({
            "status": "REPAIRED",
            "reason": source,
            "kek": kek,
            "encrypted_path": item.path,
            "output_path": str(out),
            "before": str(before),
            "after": str(after),
            "skipped": hex(skipped_bytes),
        })
        print(
            f"REPAIRED {repaired}: {out} before={before} after={after} skipped={hex(skipped_bytes)}",
            flush=True,
        )

    manifest = r.REPORTS / "video_repair_manifest_latest.csv"
    with manifest.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["status", "reason", "kek", "encrypted_path", "output_path", "before", "after", "skipped"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"DONE repaired={repaired} failed={failed} manifest={manifest}", flush=True)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
