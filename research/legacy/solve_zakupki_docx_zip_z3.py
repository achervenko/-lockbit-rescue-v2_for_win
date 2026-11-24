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
import tempfile
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

# Office ZIP local header for first member [Content_Types].xml.
# Bytes 14..25 are CRC/compressed/uncompressed sizes and vary per file.
KNOWN = {
    **{i: b for i, b in enumerate(bytes.fromhex(_case_value('81c299a5eee6f87ece8c')))},
    26: 0x13,
    27: 0x00,
    28: 0x08,
    29: 0x02,
}
name = b"[Content_Types].xml"
for i, b in enumerate(name, 30):
    KNOWN[i] = b
extra = bytes.fromhex(_case_value('cbc8f6330a3d8099d9fc'))
for i, b in enumerate(extra, 30 + len(name)):
    KNOWN[i] = b


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def solve_item(target: Path, timeout_ms: int) -> str | None:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    item = None
    files = None
    for fs in groups.values():
        for it in fs:
            if Path(it.path) == target:
                item = it
                files = fs
                break
        if item:
            break
    if item is None or files is None:
        print("not_scanned")
        return None
    ks = build_group_keystream(files)
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(target)
    start = fei_len - 64
    missing = [off for off in range(start, fei_len) if off not in ks]
    print(f"target={out_rel_for(target)} fei={fei_len} cov={rdt.contiguous(ks)} missing={missing}", flush=True)
    unknown = {off: z3.BitVec(f"ks_{off}", 8) for off in missing}
    fek_bytes = []
    for i in range(64):
        off = start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])
    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    words = salsa20_words_z3(state)
    enc_head = target.read_bytes()[:64]
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for idx, plain in KNOWN.items():
        if idx >= len(enc_head):
            continue
        solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(enc_head[idx] ^ plain, 8))
    status = solver.check()
    print(f"z3_status={status}", flush=True)
    if status != z3.sat:
        return None
    model = solver.model()
    learned = dict(ks)
    for off, var in unknown.items():
        learned[off] = model.eval(var).as_long()
    fek = bytes(fei_ct[start + i] ^ learned[start + i] for i in range(64))
    return fek.hex()


def store(target: Path, fek_hex: str) -> bool:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    item = next(it for fs in groups.values() for it in fs if Path(it.path) == target)
    before, after, skipped, _ = rdt.chunking_params_for(item, {})
    with tempfile.TemporaryDirectory(prefix="zak_docx_z3_") as td:
        tmp = Path(td) / out_rel_for(target).name
        with rdt.helper_path(target, "direct") as direct_path:
            ok = rdt.direct_decrypt_with_timeout(
                rdt.REPO / "direct-decrypt.exe",
                direct_path,
                tmp,
                fek_hex,
                max(0, before - 1),
                max(0, after - 1),
                hex(skipped),
            )
        valid = ok and rdt.validate_recovered(tmp, "docx")
        print(f"direct_ok={ok} valid={valid} head={(tmp.read_bytes()[:16].hex() if tmp.exists() else '')}", flush=True)
        if not valid:
            return False
        out = OUT_ROOT / out_rel_for(target)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
        print(f"RECOVERED {out}", flush=True)
        return True


def main() -> int:
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(_case_value('fca49d09650048d8074c'))
    timeout_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 300000
    fek = solve_item(target, timeout_ms)
    if not fek:
        return 2
    return 0 if store(target, fek) else 2


if __name__ == "__main__":
    raise SystemExit(main())
