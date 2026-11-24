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

import z3
import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
EXT = ".xzg9VRelb"


JPEG_EXIF_KNOWN = {
    0: 0xFF,
    1: 0xD8,
    2: 0xFF,
    3: 0xE1,
    6: ord("E"),
    7: ord("x"),
    8: ord("i"),
    9: ord("f"),
    10: 0,
    11: 0,
    12: ord("I"),
    13: ord("I"),
    14: 0x2A,
    15: 0,
    16: 8,
    17: 0,
    18: 0,
    19: 0,
}

JPEG_JFIF_THUMB_KNOWN = {
    0: 0xFF,
    1: 0xD8,
    2: 0xFF,
    3: 0xE0,
    4: 0x00,
    5: 0x10,
    6: ord("J"),
    7: ord("F"),
    8: ord("I"),
    9: ord("F"),
    10: 0x00,
    11: 0x01,
    12: 0x01,
    13: 0x01,
    14: 0x00,
    17: 0x00,
    18: 0x00,
    19: 0xFF,
    20: 0xDB,
    21: 0x00,
    22: 0x43,
    23: 0x00,
}


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def item_words(item: lr.EncryptedFile, ks: dict[int, int], unknown_ks: dict[int, z3.BitVecRef]) -> tuple[list[z3.BitVecRef], bytes]:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    fek_start = fei_len - 64
    fek_bytes = []
    for i in range(64):
        off = fek_start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    return salsa20_words_z3(state), Path(item.path).read_bytes()[:64]


def main() -> int:
    kek_arg = sys.argv[1] if len(sys.argv) > 1 else _case_value('bf5b7f2a2985a4a2d1f3')
    take = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    timeout_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 180000
    mode = sys.argv[4] if len(sys.argv) > 4 else "exif"
    groups, scanned, skipped = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    print(f"scanned={scanned} groups={len(groups)} skipped={skipped}", flush=True)
    files = groups.get(kek_arg)
    if not files:
        print(f"no_kek {kek_arg}", flush=True)
        return 2
    ks = build_group_keystream(files)
    cov = rdt.contiguous(ks)
    candidates = []
    for item in files:
        rel = out_rel_for(Path(item.path))
        if (OUT_ROOT / rel).exists() or rel.suffix.lower() not in {".jpg", ".jpeg"}:
            continue
        gap = max(0, item.fei_len - cov)
        candidates.append((gap, item.fei_len, Path(item.path).stat().st_size, rel, item))
    if mode == "thumb":
        candidates = [row for row in candidates if ".@__thumb" in row[3].parts]
    candidates.sort(key=lambda row: (row[0], row[1], row[2]))
    chosen = candidates[:take]
    if not chosen:
        print("no_candidates", flush=True)
        return 2
    max_off = max(item.fei_len for *_, item in chosen) - 1
    unknown_offsets = list(range(cov, max_off + 1))
    unknown_ks = {off: z3.BitVec(f"ks_{off}", 8) for off in unknown_offsets}
    print(f"kek={kek_arg} mode={mode} cov={cov} chosen={len(chosen)} unknown={len(unknown_offsets)} offsets={unknown_offsets[0]}..{unknown_offsets[-1]}", flush=True)
    for gap, fei, size, rel, _ in chosen:
        print(f"  target gap={gap} fei={fei} size={size} {rel}", flush=True)

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    known = JPEG_JFIF_THUMB_KNOWN if mode == "thumb" else JPEG_EXIF_KNOWN
    for _, _, _, rel, item in chosen:
        words, enc_head = item_words(item, ks, unknown_ks)
        for idx, plain in known.items():
            solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(enc_head[idx] ^ plain, 8))
    status = solver.check()
    print(f"z3_status={status}", flush=True)
    if status != z3.sat:
        return 2
    model = solver.model()
    vals = bytes(model.eval(unknown_ks[off]).as_long() for off in unknown_offsets)
    print(f"tail_offsets={unknown_offsets[0]}..{unknown_offsets[-1]} tail_hex={vals.hex()}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
