from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import json
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
TARGET_KEKS = [_case_value('4906e8c091d91acf1ae1'), _case_value('fc3a6afde96d79d41911'), _case_value('5a95466376149ac63974'), _case_value('334d517b17c31441017e')]


def merge_ks(dst: dict[int, int], off: int, value: int, source: str, conflicts: list[str]) -> None:
    old = dst.get(off)
    if old is not None and old != value:
        conflicts.append(f"offset={off} old={old:02x} new={value:02x} source={source}")
        return
    dst[off] = value


def build_seed_for_group(kek: str, files: list[lr.EncryptedFile]) -> dict[str, object]:
    base = rdt.run_dump_ks(max(files, key=lambda f: f.coverage))
    ks = {i: b for i, b in enumerate(base or b"")}
    conflicts: list[str] = []
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)

    # Learn from exact known-pair outputs already present locally. This is the
    # part that the small PC package can miss when it lacks the full recovered tree.
    for _ in range(12):
        learned = 0
        for item in sorted(files, key=lambda it: (it.fei_len, it.original_name.lower())):
            out = rdt.output_path_for(item)
            if not out.exists() or not out.is_file():
                continue
            try:
                _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
                if out.stat().st_size != body_end:
                    continue
            except Exception:
                continue
            fek = rdt.recover_fek_from_known_pair(item, ks)
            if not fek:
                continue
            before = len(ks)
            rdt.learn_fek(ks, item, fek)
            learned += max(0, len(ks) - before)
        if learned == 0:
            break

    # Fold in the special GPU chain found for 4f, because it was learned outside
    # the generic run_dump_ks path.
    if kek == _case_value('334d517b17c31441017e'):
        p = REPORTS / "sklad_4f_after_gap3_keystream.txt"
        if p.exists():
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("ks90_final="):
                    blob = bytes.fromhex(line.split("=", 1)[1].strip())
                    for i, b in enumerate(blob, 90):
                        merge_ks(ks, i, b, str(p), conflicts)

    ranges = []
    known = sorted(ks)
    if known:
        start = prev = known[0]
        for off in known[1:]:
            if off == prev + 1:
                prev = off
                continue
            ranges.append([start, prev])
            start = prev = off
        ranges.append([start, prev])

    return {
        "kek": kek,
        "contiguous_coverage": rdt.contiguous(ks),
        "known_count": len(ks),
        "ranges": ranges,
        "ks": {str(off): f"{val:02x}" for off, val in sorted(ks.items())},
        "conflicts": conflicts,
    }


def main() -> int:
    groups, scanned, skipped = lr.scan_source(SRC_ROOT / "СКЛАД", [rdt.EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    seeds = {
        "format": "lockbit-rescue-sparse-keystream-v1",
        "source": str(SRC_ROOT / "СКЛАД"),
        "scanned": scanned,
        "skipped": skipped,
        "groups": {},
    }
    for kek in TARGET_KEKS:
        files = groups.get(kek)
        if not files:
            continue
        seed = build_seed_for_group(kek, files)
        seeds["groups"][kek] = seed
        print(f"kek={kek} cov={seed['contiguous_coverage']} known={seed['known_count']} ranges={seed['ranges'][:5]}")
        if seed["conflicts"]:
            print(f"  conflicts={len(seed['conflicts'])}")
    out = REPORTS / "sklad_z3_keystream_seed.json"
    out.write_text(json.dumps(seeds, ensure_ascii=False, indent=2), encoding="utf-8")
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
