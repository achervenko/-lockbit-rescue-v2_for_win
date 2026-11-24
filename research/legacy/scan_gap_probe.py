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
from pathlib import Path

sys.path.insert(0, _project_path('research/legacy'))
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as r


def original_rel(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(r.SRC_ROOT)
    return Path(str(rel)[: -len(r.EXT)])


def main() -> int:
    os.environ["RECOVER_FOLDER"] = "SCAN"
    groups, _, _ = lr.scan_source(r.SRC_ROOT / "SCAN", [r.EXT], r.SCAN_EXTS, True, 1, r.MAX_SIZE_BYTES, workers=1)
    for kek, batch in groups.items():
        if kek != _case_value('e1d320264d75dae35a35'):
            continue
        batch = sorted(batch, key=lambda f: (f.fei_len, original_rel(f).name.lower()))
        ks = {}
        oracle = max(batch, key=lambda f: f.coverage)
        name_ks = r.run_dump_ks(oracle)
        for off, val in enumerate(name_ks or b""):
            ks[off] = val
        for item in sorted(batch, key=lambda f: f.coverage, reverse=True):
            more = r.run_dump_ks(item)
            if not more:
                continue
            for off, val in enumerate(more):
                r.merge_ks(ks, off, val)
        r.learn_name_len_metadata(ks, batch)
        r.learn_stable_metadata_profiles(ks, batch)
        for item in batch[:20]:
            out = r.output_path_for(item)
            recovered = out.exists() and out.stat().st_size > 0 and r.validate_recovered(out, "pdf")
            gap = max(0, item.fei_len - r.contiguous(ks))
            fei_len, fei_offset, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
            head = Path(item.path).read_bytes()[:64]
            print(
                f"rel={original_rel(item)} recovered={recovered} fei_len={fei_len} "
                f"coverage={r.contiguous(ks)} gap={gap} body_end={body_end} "
                f"fei_offset={fei_offset}"
            )
            print(f"  enc_head={head.hex()}")
            start = fei_len - 64
            missing = [off for off in range(start, fei_len) if off not in ks]
            print(f"  fek_start={start} missing={missing}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
