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


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def solve_with_plain(target: Path, plain: Path, timeout_ms: int) -> str | None:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    target_item = None
    target_files = None
    for _, files in groups.items():
        for item in files:
            if Path(item.path) == target:
                target_item = item
                target_files = files
                break
        if target_item:
            break
    if not target_item or target_files is None:
        print("target_not_scanned")
        return None
    ks = build_group_keystream(target_files)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(target)
    if plain.stat().st_size != body_end:
        print(f"plain_size_mismatch plain={plain.stat().st_size} body={body_end}")
        return None
    start = fei_len - 64
    missing = [off for off in range(start, fei_len) if off not in ks]
    print(f"fei={fei_len} cov={rdt.contiguous(ks)} missing={missing}", flush=True)
    unknown_ks = {off: z3.BitVec(f"ks_{off}", 8) for off in missing}
    fek_bytes = []
    for i in range(64):
        off = start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    words = salsa20_words_z3(state)
    enc_head = target.read_bytes()[:64]
    plain_head = plain.read_bytes()[:64]
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for idx, (e, p) in enumerate(zip(enc_head, plain_head)):
        solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(e ^ p, 8))
    status = solver.check()
    print(f"z3_status={status}", flush=True)
    if status != z3.sat:
        return None
    model = solver.model()
    learned = dict(ks)
    for off, var in unknown_ks.items():
        learned[off] = model.eval(var).as_long()
    fek = bytes(fei_ct[start + i] ^ learned[start + i] for i in range(64))
    if rdt.salsa20_block(fek) != bytes(a ^ b for a, b in zip(enc_head, plain_head)):
        print("python_verify_failed")
        return None
    return fek.hex()


def decrypt(target: Path, fek_hex: str) -> Path | None:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    item = next(item for files in groups.values() for item in files if Path(item.path) == target)
    ks = {}
    before, after, skipped, _ = rdt.chunking_params_for(item, ks)
    tmpdir = tempfile.mkdtemp(prefix="zak_ext_pair_")
    tmp = Path(tmpdir) / out_rel_for(target).name
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
    print(f"direct_ok={ok} tmp={tmp}", flush=True)
    return tmp if ok and tmp.exists() else None


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: script <target-encrypted> <plain-candidate> [timeout_ms]")
        return 2
    target = Path(sys.argv[1])
    plain = Path(sys.argv[2])
    timeout_ms = int(sys.argv[3]) if len(sys.argv) > 3 else 300000
    fek = solve_with_plain(target, plain, timeout_ms)
    if not fek:
        return 2
    tmp = decrypt(target, fek)
    if not tmp:
        return 2
    same = tmp.read_bytes() == plain.read_bytes()
    print(f"same_as_plain={same}", flush=True)
    if same:
        out = OUT_ROOT / out_rel_for(target)
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
        print(f"RECOVERED_BY_EXTERNAL_PAIR {out}", flush=True)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
