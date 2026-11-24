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

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
import solve_zakupki_mp4_body_constraints_z3 as mp4z3


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def constraint_count(item: lr.EncryptedFile, ks: dict[int, int]) -> tuple[int, int, int, int]:
    enc = Path(item.path)
    fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
    data = enc.read_bytes()[:body_end]
    moov_pos = data.rfind(b"moov")
    if moov_pos < 4:
        return 0, 0, 0, 0
    moov_start = moov_pos - 4
    moov_size = int.from_bytes(data[moov_start:moov_start + 4], "big")
    if moov_size <= 8 or moov_start + moov_size > body_end:
        return 0, 0, 0, 0
    moov = data[moov_start:moov_start + moov_size]
    traks = [n for n in mp4z3.parse_tree(moov)[0][2] if n[0] == b"trak"]
    parsed = None
    for trak in traks:
        try:
            parsed = mp4z3.parse_tables(mp4z3.get_stbl(trak))
            break
        except Exception:
            continue
    if parsed is None:
        return 0, 0, 0, 0
    sizes, offsets, keyset = parsed
    before, after, skipped, _ = rdt.chunking_params_for(item, ks)
    wins = mp4z3.encrypted_windows(body_end, before, after, skipped)
    sample_constraints = 0
    encrypted_samples = 0
    blocks = set()
    for sample_no, (off, size) in enumerate(zip(offsets, sizes), start=1):
        if size <= 4:
            continue
        touched = False
        for j in range(5):
            stream_off = mp4z3.body_to_stream_index(off + j, wins)
            if stream_off is not None:
                sample_constraints += 1
                blocks.add(stream_off // 64)
                touched = True
        if touched:
            encrypted_samples += 1
    header_constraints = 0
    for i in range(40):
        stream_off = mp4z3.body_to_stream_index(i, wins)
        if stream_off is not None:
            header_constraints += 1
            blocks.add(stream_off // 64)
    return sample_constraints + header_constraints, encrypted_samples, len(wins), len(blocks)


def main() -> int:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    rows = []
    for kek, files in groups.items():
        ks = build_group_keystream(files)
        cov = rdt.contiguous(ks)
        for item in files:
            enc = Path(item.path)
            rel = out_rel_for(enc)
            if rel.suffix.lower() != ".mp4":
                continue
            if (OUT_ROOT / rel).exists():
                continue
            fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            gap = max(0, fei_len - cov)
            constraints, samples, windows, blocks = constraint_count(item, ks)
            density = constraints / max(1, blocks)
            rows.append((gap, -density, blocks, -constraints, -samples, -body_end, kek, fei_len, cov, constraints, samples, windows, density, rel, enc))
    rows.sort()
    print("gap | constraints | blocks | density | samples | windows | fei | cov | MB | kek | rel | path")
    for row in rows[:30]:
        gap, neg_density, blocks, neg_constraints, neg_samples, neg_body, kek, fei_len, cov, constraints, samples, windows, density, rel, enc = row
        print(
            f"{gap} | {constraints} | {blocks} | {density:.2f} | {samples} | {windows} | {fei_len} | {cov} | "
            f"{(-neg_body) / 1024 / 1024:.1f} | {kek} | {rel} | {enc}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
