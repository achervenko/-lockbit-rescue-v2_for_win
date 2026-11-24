from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path('research/legacy'))
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as r

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def main() -> int:
    folder = os.environ.get("RECOVER_FOLDER", "SCAN")
    src = r.SRC_ROOT / folder
    dst = r.DST / folder
    groups, scanned, skipped = lr.scan_source(
        src, [r.EXT], r.SCAN_EXTS, True, 1, r.MAX_SIZE_BYTES, workers=1
    )
    files = [item for batch in groups.values() for item in batch]

    def original_rel(item: lr.EncryptedFile) -> Path:
        enc = Path(item.path)
        rel = enc.relative_to(r.SRC_ROOT)
        return Path(str(rel)[: -len(r.EXT)])

    def is_recovered(item: lr.EncryptedFile) -> bool:
        out = r.output_path_for(item)
        ext = r.infer_ext(original_rel(item).name)
        return out.exists() and out.stat().st_size > 0 and r.validate_recovered(out, ext)

    total_files = len(files)
    total_bytes = sum(lr.read_fei_ciphertext(Path(item.path))[2] for item in files)
    recovered = [item for item in files if is_recovered(item)]
    missing = [item for item in files if not is_recovered(item)]
    recovered_bytes = sum(lr.read_fei_ciphertext(Path(item.path))[2] for item in recovered)

    print(f"SCANNED files={scanned} groups={len(groups)} skipped={skipped}")
    print(
        f"RECOVERED files={len(recovered)}/{total_files} "
        f"({len(recovered) / total_files * 100:.2f}%)"
    )
    print(
        f"RECOVERED volume={recovered_bytes / 1024**2:.2f}/"
        f"{total_bytes / 1024**2:.2f} MB "
        f"({recovered_bytes / total_bytes * 100:.2f}%)"
    )

    for kek, batch in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        have = sum(1 for item in batch if is_recovered(item))
        ks: dict[int, int] = {}
        oracle = None
        base_cov = 0
        for candidate in sorted(batch, key=lambda f: f.coverage, reverse=True):
            name_ks = r.run_dump_ks(candidate)
            if name_ks:
                oracle = candidate
                base_cov = candidate.coverage
                for off, val in enumerate(name_ks):
                    ks[off] = val
                break
        if oracle is not None:
            for candidate in sorted(batch, key=lambda f: f.coverage, reverse=True):
                if candidate.path == oracle.path:
                    continue
                more = r.run_dump_ks(candidate)
                if not more:
                    continue
                for off, val in enumerate(more):
                    r.merge_ks(ks, off, val)
            r.learn_name_len_metadata(ks, batch)
            r.learn_stable_metadata_profiles(ks, batch)
            for candidate in sorted(batch, key=lambda f: f.fei_len):
                if is_recovered(candidate):
                    r.learn_existing_item(candidate, oracle, ks, base_cov)
        cov = r.contiguous(ks)
        remain = [item for item in batch if not is_recovered(item)]
        gaps = Counter(max(0, item.fei_len - cov) for item in remain)
        min_gap = min(gaps, default=0)
        exts = Counter(r.infer_ext(original_rel(item).name) for item in batch)
        print(
            f"GROUP {kek}: {have}/{len(batch)} cov={cov} base_cov={base_cov} "
            f"remaining={len(remain)} min_gap={min_gap} gaps={dict(sorted(gaps.items())[:8])} "
            f"types={dict(exts)}"
        )
        for item in sorted(remain, key=lambda f: (max(0, f.fei_len - cov), f.fei_len, original_rel(f).name.lower()))[:10]:
            print(
                f"  NEXT gap={max(0, item.fei_len - cov)} fei_len={item.fei_len} "
                f"size={lr.read_fei_ciphertext(Path(item.path))[2] / 1024**2:.2f}MB "
                f"{original_rel(item)}"
            )

    for old in dst.rglob("*НЕ_ВОССТАНОВЛЕНО*.txt"):
        try:
            old.unlink()
        except OSError:
            pass
    dst.mkdir(parents=True, exist_ok=True)
    report = dst / "НЕ_ВОССТАНОВЛЕНО.txt"
    with report.open("w", encoding="utf-8") as fh:
        fh.write(f"{folder}: не восстановлено\n")
        fh.write(
            f"Файлы: {len(recovered)}/{total_files} "
            f"({len(recovered) / total_files * 100:.2f}%)\n"
        )
        fh.write(
            f"Объем: {recovered_bytes / 1024**2:.2f}/"
            f"{total_bytes / 1024**2:.2f} MB "
            f"({recovered_bytes / total_bytes * 100:.2f}%)\n\n"
        )
        for item in sorted(missing, key=lambda f: str(original_rel(f)).lower()):
            rel = original_rel(item)
            if len(rel.parts) > 1:
                rel = Path(*rel.parts[1:])
            fh.write(str(rel).replace("\\", "/") + "\n")
    print(f"REPORT {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
