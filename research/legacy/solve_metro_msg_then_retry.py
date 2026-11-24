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

os.environ["RECOVER_FOLDER"] = "МЕТРОЛОГИЯ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import z3
import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


ENC_ROOT = Path(_case_value('1417be6d1995580356a1'))
OUT_ROOT = Path(_case_value('f3c3aa9452e88374e1f9'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
EXT = ".xzg9VRelb"

OLE_PREFIX = bytes.fromhex(
    _case_value('0e0a8cb5d83604cf2693')
)


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def build_group_keystream(files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle_ks = None
    for candidate in sorted(files, key=lambda f: f.coverage, reverse=True):
        oracle_ks = rdt.run_dump_ks(candidate)
        if oracle_ks:
            break
    if not oracle_ks:
        return {}
    ks = {off: val for off, val in enumerate(oracle_ks)}
    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        more = rdt.run_dump_ks(item)
        if not more:
            continue
        for off, val in enumerate(more):
            old = ks.get(off)
            if old is None:
                ks[off] = val
            elif old != val:
                ks.pop(off, None)
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    for item in sorted(files, key=lambda f: f.fei_len):
        out = OUT_ROOT / out_rel_for(Path(item.path))
        if not out.exists():
            continue
        fek = rdt.recover_fek_from_known_pair(item, ks)
        if fek:
            rdt.learn_fek(ks, item, fek)
    return ks


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def solve_msg(files: list[lr.EncryptedFile], ks: dict[int, int], timeout_ms: int) -> tuple[lr.EncryptedFile, str, dict[int, int]] | None:
    targets = []
    for item in files:
        enc = Path(item.path)
        rel = out_rel_for(enc)
        if rel.suffix.lower() == ".msg" and not (OUT_ROOT / rel).exists():
            targets.append(item)
    if not targets:
        return None

    item = min(targets, key=lambda f: f.fei_len)
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    fek_start = fei_len - 64
    missing = [off for off in range(fek_start, fei_len) if off not in ks]
    print(f"MSG target={out_rel_for(Path(item.path))} fei={fei_len} missing={missing}", flush=True)
    if len(missing) > 12:
        print("too_many_missing_for_z3", flush=True)
        return None

    unknown_ks = {off: z3.BitVec(f"ks_{off}", 8) for off in missing}
    fek_bytes = []
    for i in range(64):
        off = fek_start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])

    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    out_words = salsa20_words_z3(state)
    enc_head = Path(item.path).read_bytes()[:64]

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for idx, plain in enumerate(OLE_PREFIX):
        expected = enc_head[idx] ^ plain
        solver.add(byte_from_word(out_words[idx // 4], idx) == z3.BitVecVal(expected, 8))

    status = solver.check()
    print(f"z3_status={status}", flush=True)
    if status != z3.sat:
        return None

    model = solver.model()
    learned = dict(ks)
    for off, var in unknown_ks.items():
        learned[off] = model.eval(var).as_long()

    fek = bytearray(64)
    for i in range(64):
        off = fek_start + i
        fek[i] = fei_ct[off] ^ learned[off]
    keyblock = rdt.salsa20_block(bytes(fek))
    if bytes(a ^ b for a, b in zip(enc_head[: len(OLE_PREFIX)], keyblock[: len(OLE_PREFIX)])) != OLE_PREFIX:
        print("python_verify_failed", flush=True)
        return None

    return item, bytes(fek).hex(), learned


def decrypt_and_store(item: lr.EncryptedFile, fek_hex: str) -> bool:
    before, after, skipped, source = rdt.chunking_params_for(item, {})
    with tempfile.TemporaryDirectory(prefix="metro_msg_") as td:
        tmp = Path(td) / "dec.msg"
        with rdt.helper_path(Path(item.path), "direct") as direct_path:
            ok = rdt.direct_decrypt_with_timeout(
                rdt.REPO / "direct-decrypt.exe",
                direct_path,
                tmp,
                fek_hex,
                max(0, before - 1),
                max(0, after - 1),
                hex(skipped),
            )
        if not ok or not rdt.validate_recovered(tmp, "msg"):
            print(f"msg_direct_failed ok={ok} head={(tmp.read_bytes()[:16].hex() if tmp.exists() else '')}", flush=True)
            return False
        out = OUT_ROOT / out_rel_for(Path(item.path))
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
        print(f"MSG_RECOVERED {out}", flush=True)
        return True


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    timeout_ms = int(os.environ.get("METRO_Z3_TIMEOUT_MS", "300000"))
    groups, scanned, skipped = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    print(f"scanned={scanned} groups={len(groups)} skipped={skipped}", flush=True)
    recovered = 0
    for kek, files in groups.items():
        ks = build_group_keystream(files)
        print(f"kek={kek} cov={rdt.contiguous(ks)} sparse={len(ks)}", flush=True)
        solved = solve_msg(files, ks, timeout_ms)
        if not solved:
            continue
        item, fek_hex, learned = solved
        if decrypt_and_store(item, fek_hex):
            recovered += 1
            new_bytes = sorted(set(learned) - set(ks))
            print(f"new_ks_offsets={new_bytes}", flush=True)
    print(f"recovered={recovered}", flush=True)
    return 0 if recovered else 2


if __name__ == "__main__":
    raise SystemExit(main())
