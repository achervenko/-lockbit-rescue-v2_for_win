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
from collections import defaultdict
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
REC_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def block_words_for(fek_bytes, block_index: int):
    state = [word_from_bytes(fek_bytes[i * 4:i * 4 + 4]) for i in range(16)]
    state[8] = state[8] + z3.BitVecVal(block_index, 32)
    return salsa20_words_z3(state)


def jpeg_kind(data: bytes) -> str:
    if data.startswith(b"\xff\xd8\xff\xe1") and b"Exif\x00\x00" in data[:32]:
        return "exif"
    if data.startswith(b"\xff\xd8\xff\xe0") and b"JFIF\x00" in data[:32]:
        return "jfif"
    return "other"


def build_templates(kind: str, limit: int = 512, threshold: float = 0.995) -> dict[int, int]:
    rows = []
    for p in REC_ROOT.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in {".jpg", ".jpeg", ".jfif"}:
            continue
        if "_technical_reports" in p.parts:
            continue
        try:
            data = p.read_bytes()[:limit]
        except OSError:
            continue
        if len(data) >= 64 and jpeg_kind(data) == kind:
            rows.append(data)
    print(f"template_kind={kind} sources={len(rows)}", flush=True)
    if len(rows) < 20:
        return {}
    usable = min(limit, min(len(r) for r in rows))
    templ = {}
    for off in range(usable):
        counts = defaultdict(int)
        for row in rows:
            counts[row[off]] += 1
        val, cnt = max(counts.items(), key=lambda kv: kv[1])
        if cnt / len(rows) >= threshold:
            templ[off] = val
    # Keep only the low-entropy header area. Entropy data after SOS is not stable enough.
    return {off: val for off, val in templ.items() if off < 256}


def solve(kek_arg: str, kind: str, take: int, timeout_ms: int) -> int:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups[kek_arg]
    ks = build_group_keystream(files)
    cov = rdt.contiguous(ks)
    templ = build_templates(kind)
    if not templ:
        print("no_template")
        return 2
    print(f"template_bytes={len(templ)} max_off={max(templ)} first={list(templ.items())[:20]}", flush=True)
    candidates = []
    for item in files:
        rel = out_rel_for(Path(item.path))
        if (OUT_ROOT / rel).exists() or rel.suffix.lower() not in {".jpg", ".jpeg"}:
            continue
        is_thumb = ".@__thumb" in rel.parts
        if kind == "jfif" and not is_thumb:
            continue
        if kind == "exif" and is_thumb:
            continue
        candidates.append((max(0, item.fei_len - cov), item.fei_len, Path(item.path).stat().st_size, rel, item))
    candidates.sort(key=lambda row: (row[0], row[1], row[2]))
    chosen = candidates[:take]
    if not chosen:
        print("no_candidates")
        return 2
    max_off = max(item.fei_len for *_, item in chosen) - 1
    unknown_offsets = list(range(cov, max_off + 1))
    unknown = {off: z3.BitVec(f"ks_{off}", 8) for off in unknown_offsets}
    print(f"kek={kek_arg} cov={cov} kind={kind} chosen={len(chosen)} unknown={len(unknown_offsets)} {unknown_offsets[:3]}..{unknown_offsets[-3:]}", flush=True)

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    block_cache = {}
    for gap, fei, size, rel, item in chosen:
        print(f"  target gap={gap} fei={fei} size={size} rel={rel}", flush=True)
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])
        enc = Path(item.path).read_bytes()[: min(body_end, max(templ) + 1)]
        for off, plain in templ.items():
            if off >= len(enc):
                continue
            block = off // 64
            key = (item.path, block)
            if key not in block_cache:
                block_cache[key] = block_words_for(fek_bytes, block)
            word = block_cache[key][(off % 64) // 4]
            solver.add(byte_from_word(word, off % 64) == z3.BitVecVal(enc[off] ^ plain, 8))
    print(f"z3_blocks={len(block_cache)}", flush=True)
    status = solver.check()
    print(f"z3_status={status}", flush=True)
    if status != z3.sat:
        return 2
    model = solver.model()
    tail = bytes(model.eval(unknown[off]).as_long() for off in unknown_offsets)
    print(f"tail_offsets={unknown_offsets[0]}..{unknown_offsets[-1]} tail={tail.hex()}")
    return 0


def main() -> int:
    kek = sys.argv[1] if len(sys.argv) > 1 else _case_value('bf5b7f2a2985a4a2d1f3')
    kind = sys.argv[2] if len(sys.argv) > 2 else "exif"
    take = int(sys.argv[3]) if len(sys.argv) > 3 else 4
    timeout_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 240000
    return solve(kek, kind, take, timeout_ms)


if __name__ == "__main__":
    raise SystemExit(main())
