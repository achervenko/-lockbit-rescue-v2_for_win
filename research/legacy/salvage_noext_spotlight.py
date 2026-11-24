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
import shutil
import sys
from pathlib import Path

FOLDER = os.environ.get("RECOVER_FOLDER", "ЗАКУПКИ")
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from salvage_exploitation_interval_params import decrypt_interval


ENC_ROOT = Path(_case_value('f6af7da1ad90629ee69b')) / FOLDER
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2')) / FOLDER
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def main() -> int:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, True, 1, rdt.MAX_SIZE_BYTES, workers=1)
    restored = 0
    for kek, files in sorted(groups.items()):
        ks = build_group_keystream(files)
        for item in files:
            enc = Path(item.path)
            rel = out_rel_for(enc)
            out = OUT_ROOT / rel
            if out.exists() or rel.suffix:
                continue
            if max(0, item.fei_len - rdt.contiguous(ks)) != 0:
                continue
            fek_hex = rdt.derive_fek_from_ks(ks, item)
            if not fek_hex:
                continue
            before, after, skipped, source = rdt.chunking_params_for(item, ks)
            data = decrypt_interval(enc, fek_hex, before, after, skipped)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
            restored += 1
            print(f"RESTORED_NOEXT {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')} {len(data)} {source}", flush=True)
    print(f"restored={restored}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
