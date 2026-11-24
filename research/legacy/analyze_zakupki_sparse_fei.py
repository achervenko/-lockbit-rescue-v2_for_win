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
import subprocess
import sys
from collections import Counter
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
PACKER = Path(_project_path('research/legacy/aplib_name_pack.exe'))
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def ranges(keys: list[int]) -> str:
    if not keys:
        return ""
    keys = sorted(keys)
    out = []
    s = p = keys[0]
    for k in keys[1:]:
        if k == p + 1:
            p = k
            continue
        out.append(f"{s}" if s == p else f"{s}-{p}")
        s = p = k
    out.append(f"{s}" if s == p else f"{s}-{p}")
    return ",".join(out)


def pack_names(names: list[str]) -> list[bytes | None]:
    result = subprocess.run(
        [str(PACKER), "--batch"],
        input="\n".join("hex:" + n.encode("utf-8").hex() for n in names) + "\n",
        capture_output=True,
        text=True,
        timeout=max(30, len(names) // 100 + 30),
    )
    out: list[bytes | None] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 4 and parts[0] == "OK":
            out.append(bytes.fromhex(parts[3]))
        else:
            out.append(None)
    out.extend([None] * (len(names) - len(out)))
    return out[: len(names)]


def add_candidate(candidates: dict[int, set[int]], off: int, val: int) -> None:
    candidates.setdefault(off, set()).add(val)


def main() -> int:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    rows = []
    for kek, files in sorted(groups.items()):
        ks = build_group_keystream(files)
        base_known = set(ks)
        candidates: dict[int, set[int]] = {}

        packed = pack_names([it.original_name for it in files])
        for item, blob in zip(files, packed):
            if blob is None or len(blob) != item.coverage:
                continue
            try:
                _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
            except Exception:
                continue
            for off, plain in enumerate(blob):
                add_candidate(candidates, off, fei_ct[off] ^ plain)
            plain_meta = rdt.stable_metadata_plaintext(item)
            if plain_meta is None:
                plain_meta = int(item.coverage).to_bytes(2, "little")
            base = item.coverage
            if base + len(plain_meta) <= len(fei_ct):
                for i, plain in enumerate(plain_meta):
                    add_candidate(candidates, base + i, fei_ct[base + i] ^ plain)

        inferred = dict(ks)
        conflicts = []
        for off, values in sorted(candidates.items()):
            if len(values) != 1:
                conflicts.append(off)
                continue
            val = next(iter(values))
            if off in inferred and inferred[off] != val:
                conflicts.append(off)
            else:
                inferred[off] = val

        remaining = [it for it in files if not (OUT_ROOT / out_rel_for(Path(it.path))).exists()]
        for item in sorted(remaining, key=lambda it: (max(0, it.fei_len - rdt.contiguous(inferred)), it.fei_len, it.original_name.lower()))[:60]:
            enc = Path(item.path)
            fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            start = fei_len - 64
            fek_offsets = list(range(start, fei_len))
            known_fek = [o for o in fek_offsets if o in inferred]
            missing_fek = [o for o in fek_offsets if o not in inferred]
            sparse_extra = sorted(set(inferred) - set(range(rdt.contiguous(inferred))))
            rows.append(
                {
                    "kek": kek,
                    "rel": str(out_rel_for(enc)),
                    "ext": out_rel_for(enc).suffix.lower().lstrip("."),
                    "body_mb": f"{body_end / 1024 / 1024:.2f}",
                    "fei_len": fei_len,
                    "contiguous": rdt.contiguous(inferred),
                    "known_total": len(inferred),
                    "max_known": max(inferred) if inferred else -1,
                    "known_ranges": ranges(sorted(inferred)),
                    "sparse_after_contiguous": ranges(sparse_extra),
                    "fek_start": start,
                    "known_fek": len(known_fek),
                    "missing_fek": len(missing_fek),
                    "missing_fek_ranges": ranges(missing_fek),
                    "conflicts": len(conflicts),
                }
            )

        print(
            f"{kek}: files={len(files)} rem={len(remaining)} contig={rdt.contiguous(inferred)} "
            f"known_total={len(inferred)} max_known={max(inferred) if inferred else -1} "
            f"conflicts={len(conflicts)} sparse={ranges(sorted(set(inferred)-set(range(rdt.contiguous(inferred)))))} "
            f"rem_ext={Counter(out_rel_for(Path(it.path)).suffix.lower() for it in remaining).most_common()}"
        )

    report = REPORTS / "zakupki_sparse_fei_analysis.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = list(rows[0].keys()) if rows else ["kek"]
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
