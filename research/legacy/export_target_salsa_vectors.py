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
EXT = ".xzg9VRelb"
TARGET_KEKS = [_case_value('4906e8c091d91acf1ae1'), _case_value('fc3a6afde96d79d41911'), _case_value('5a95466376149ac63974')]


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    base = rdt.run_dump_ks(max(files, key=lambda f: f.coverage))
    if not base:
        return {}
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def export_vectors() -> list[dict[str, object]]:
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    vectors: list[dict[str, object]] = []
    for kek in TARGET_KEKS:
        files = groups.get(kek, [])
        if not files:
            continue
        ks = build_group_ks(files)
        cov = rdt.contiguous(ks)
        candidates = []
        for item in files:
            enc = Path(item.path)
            out = output_path_for(item)
            if not out.exists() or not out.is_file():
                continue
            try:
                fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
            except Exception:
                continue
            if out.stat().st_size != body_end:
                continue
            start = fei_len - 64
            missing = [off for off in range(start, fei_len) if off not in ks]
            if not missing:
                continue
            with enc.open("rb") as ef, out.open("rb") as pf:
                expected64 = bytes(a ^ b for a, b in zip(ef.read(64), pf.read(64)))
            fek_known_hex = []
            mask = []
            for i in range(64):
                off = start + i
                if off in ks:
                    fek_known_hex.append(f"{fei_ct[off] ^ ks[off]:02x}")
                    mask.append("1")
                else:
                    fek_known_hex.append("??")
                    mask.append("0")
            candidates.append(
                {
                    "missing": len(missing),
                    "fei_len": fei_len,
                    "body_size": body_end,
                    "item": item,
                    "fek_start": start,
                    "missing_offsets": missing,
                    "fek_template": "".join(fek_known_hex),
                    "known_mask_64": "".join(mask),
                    "expected_salsa20_block64_hex": expected64.hex(),
                }
            )
        candidates.sort(key=lambda r: (r["missing"], -r["body_size"]))
        for c in candidates[:8]:
            item = c.pop("item")
            vectors.append(
                {
                    "kek": kek,
                    "coverage": cov,
                    "relative_path": str(Path(item.path).relative_to(SRC_ROOT))[: -len(EXT)],
                    **c,
                }
            )
    return vectors


def main() -> int:
    out = REPORTS / "fek_prng_research_after_gpu" / "target_salsa_known_pair_vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    vectors = export_vectors()
    out.write_text(json.dumps(vectors, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"vectors={len(vectors)}")
    print(out)
    for v in vectors[:10]:
        print(f"{v['kek']} miss={v['missing']} fei={v['fei_len']} {v['relative_path']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
