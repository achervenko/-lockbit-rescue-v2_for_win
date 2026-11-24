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
import sys
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"
TARGETS = {_case_value('4906e8c091d91acf1ae1'), _case_value('fc3a6afde96d79d41911'), _case_value('5a95466376149ac63974'), _case_value('334d517b17c31441017e')}


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def build_group_ks(kek: str, files: list[lr.EncryptedFile]) -> dict[int, int]:
    base = rdt.run_dump_ks(max(files, key=lambda f: f.coverage))
    if not base:
        return {}
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)

    # Fold in the 4f GPU-chain keystream if present. This keeps the script
    # useful for before/after comparisons without changing the recovery pipeline.
    extra = REPORTS / "sklad_4f_after_gap3_keystream.txt"
    if kek == _case_value('334d517b17c31441017e') and extra.exists():
        text = extra.read_text(encoding="utf-8", errors="ignore")
        for line in text.splitlines():
            if line.startswith("ks90_final="):
                blob = bytes.fromhex(line.split("=", 1)[1].strip())
                for i, b in enumerate(blob, 90):
                    ks[i] = b
    return ks


def main() -> int:
    groups, scanned, skipped = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    rows = []
    for kek, files in sorted(groups.items()):
        if kek not in TARGETS:
            continue
        ks = build_group_ks(kek, files)
        cov = rdt.contiguous(ks)
        for item in files:
            enc = Path(item.path)
            out = output_path_for(item)
            if not out.exists() or not out.is_file():
                continue
            try:
                fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
            except Exception:
                continue
            exact_pair = out.stat().st_size == body_end
            fek_start = fei_len - 64
            if fek_start < 0:
                continue
            missing = [off for off in range(fek_start, fei_len) if off not in ks]
            known = 64 - len(missing)
            rows.append(
                {
                    "kek": kek,
                    "coverage": cov,
                    "exact_pair": str(exact_pair),
                    "missing_fek_bytes": len(missing),
                    "known_fek_bytes": known,
                    "fei_len": fei_len,
                    "fek_start": fek_start,
                    "missing_ranges": rdt.ranges(missing) if hasattr(rdt, "ranges") else ",".join(map(str, missing)),
                    "body_size": body_end,
                    "out_size": out.stat().st_size,
                    "rel": str(enc.relative_to(SRC_ROOT))[: -len(EXT)],
                }
            )
    rows.sort(key=lambda r: (r["kek"], not (r["exact_pair"] == "True"), int(r["missing_fek_bytes"]), int(r["body_size"])))
    report = REPORTS / "sklad_target_group_known_pair_constraints.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["kek"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"scanned={scanned} skipped={skipped} rows={len(rows)} report={report}")
    for kek in sorted(TARGETS):
        vals = [r for r in rows if r["kek"] == kek]
        exact = [r for r in vals if r["exact_pair"] == "True"]
        print(f"kek={kek} recovered_outputs={len(vals)} exact_pairs={len(exact)}")
        for row in exact[:10]:
            print(
                f"  miss={row['missing_fek_bytes']} fei={row['fei_len']} body={row['body_size']} "
                f"rel={row['rel']}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
