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
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORT = DST_ROOT / "_technical_reports" / "fei_fek_research" / "remaining_fek_gaps.csv"
EXT = ".xzg9VRelb"


def out_for(enc: Path) -> Path:
    return DST_ROOT / Path(str(enc.relative_to(SRC_ROOT))[: -len(EXT)])


def recover_item(item: lr.EncryptedFile, ks: dict[int, int]) -> tuple[bool, str]:
    enc = Path(item.path)
    out = out_for(enc)
    if out.exists():
        return False, "already_exists"
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(enc)
    start = fei_len - 64
    if start < 0 or not all(off in ks for off in range(start, fei_len)):
        return False, "fek_not_known"
    fek = bytes(fei_ct[start + i] ^ ks[start + i] for i in range(64)).hex()
    ext = rdt.infer_ext(item.original_name)
    before, after, skipped, source = rdt.chunking_params_for(item, ks)
    with tempfile.TemporaryDirectory(prefix="fek0_") as td:
        tmp = Path(td) / out.name
        with rdt.helper_path(enc, "direct") as direct_path:
            ok = rdt.direct_decrypt_with_timeout(
                rdt.REPO / "direct-decrypt.exe",
                direct_path,
                tmp,
                fek,
                max(0, before - 1),
                max(0, after - 1),
                hex(skipped),
            )
        valid = ok and rdt.validate_recovered(tmp, ext)
        if not valid:
            return False, f"invalid:{ext}:{before}/{after}/0x{skipped:x}/{source}"
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
        return True, f"recovered:{ext}:{before}/{after}/0x{skipped:x}/{source}"


def main() -> int:
    rows = list(csv.DictReader(REPORT.open(encoding="utf-8-sig")))
    targets = [r for r in rows if r["missing_fek_bytes"] == "0"]
    if not targets:
        print("no_missing_fek0_targets")
        return 0
    groups, _, _ = lr.scan_source(SRC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    by_path = {str(Path(item.path)): item for files in groups.values() for item in files}
    by_kek = {kek: files for kek, files in groups.items()}
    ks_cache = {}
    recovered = 0
    statuses = defaultdict(int)
    for row in sorted(targets, key=lambda r: (r["folder"], r["kek"], r["path"])):
        path = str(Path(row["path"]))
        item = by_path.get(path)
        if item is None:
            statuses["not_scanned"] += 1
            print(f"not_scanned {path}", flush=True)
            continue
        kek = row["kek"]
        if kek not in ks_cache:
            ks_cache[kek] = build_group_keystream(by_kek[kek])
        ok, status = recover_item(item, ks_cache[kek])
        statuses[status] += 1
        if ok:
            recovered += 1
        print(f"{'OK' if ok else 'NO'} {status} {path}", flush=True)
    print(f"recovered={recovered} statuses={dict(statuses)}")
    return 0 if recovered else 2


if __name__ == "__main__":
    raise SystemExit(main())
