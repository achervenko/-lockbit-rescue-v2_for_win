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
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import z3

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def build_group_ks(kek: str) -> tuple[dict[int, int], list[lr.EncryptedFile]]:
    groups, _, _ = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    files = groups[kek]
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump base ks")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks, files


def rotl32(x, n: int):
    return z3.RotateLeft(x, n)


def salsa20_words_z3(state: list[z3.BitVecRef]) -> list[z3.BitVecRef]:
    x = state[:]
    for _ in range(10):
        x[4] ^= rotl32(x[0] + x[12], 7)
        x[8] ^= rotl32(x[4] + x[0], 9)
        x[12] ^= rotl32(x[8] + x[4], 13)
        x[0] ^= rotl32(x[12] + x[8], 18)
        x[9] ^= rotl32(x[5] + x[1], 7)
        x[13] ^= rotl32(x[9] + x[5], 9)
        x[1] ^= rotl32(x[13] + x[9], 13)
        x[5] ^= rotl32(x[1] + x[13], 18)
        x[14] ^= rotl32(x[10] + x[6], 7)
        x[2] ^= rotl32(x[14] + x[10], 9)
        x[6] ^= rotl32(x[2] + x[14], 13)
        x[10] ^= rotl32(x[6] + x[2], 18)
        x[3] ^= rotl32(x[15] + x[11], 7)
        x[7] ^= rotl32(x[3] + x[15], 9)
        x[11] ^= rotl32(x[7] + x[3], 13)
        x[15] ^= rotl32(x[11] + x[7], 18)
        x[1] ^= rotl32(x[0] + x[3], 7)
        x[2] ^= rotl32(x[1] + x[0], 9)
        x[3] ^= rotl32(x[2] + x[1], 13)
        x[0] ^= rotl32(x[3] + x[2], 18)
        x[6] ^= rotl32(x[5] + x[4], 7)
        x[7] ^= rotl32(x[6] + x[5], 9)
        x[4] ^= rotl32(x[7] + x[6], 13)
        x[5] ^= rotl32(x[4] + x[7], 18)
        x[11] ^= rotl32(x[10] + x[9], 7)
        x[8] ^= rotl32(x[11] + x[10], 9)
        x[9] ^= rotl32(x[8] + x[11], 13)
        x[10] ^= rotl32(x[9] + x[8], 18)
        x[12] ^= rotl32(x[15] + x[14], 7)
        x[13] ^= rotl32(x[12] + x[15], 9)
        x[14] ^= rotl32(x[13] + x[12], 13)
        x[15] ^= rotl32(x[14] + x[13], 18)
    return [x[i] + state[i] for i in range(16)]


def word_from_bytes(bs: list[int | z3.BitVecRef]):
    out = z3.BitVecVal(0, 32)
    for i, b in enumerate(bs):
        bv = z3.BitVecVal(b, 8) if isinstance(b, int) else b
        out = out | (z3.ZeroExt(24, bv) << (8 * i))
    return out


def solve_item(enc: Path, timeout_ms: int = 300000, words_limit: int = 16) -> dict[str, str]:
    item_kek = None
    target_item = None
    groups, _, _ = lr.scan_source(
        SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    for kek, files in groups.items():
        for item in files:
            if Path(item.path) == enc:
                item_kek = kek
                target_item = item
                break
        if target_item:
            break
    if not target_item or not item_kek:
        raise RuntimeError("target not in scan")

    ks, _ = build_group_ks(item_kek)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
    out = output_path_for(enc)
    if not out.exists():
        raise RuntimeError("output/plain pair does not exist")
    if out.stat().st_size != body_end:
        raise RuntimeError("pair size mismatch")

    fek_start = fei_len - 64
    known_fek: list[int | None] = []
    missing_positions = []
    for i in range(64):
        off = fek_start + i
        if off in ks:
            known_fek.append(fei_ct[off] ^ ks[off])
        else:
            known_fek.append(None)
            missing_positions.append(i)

    with enc.open("rb") as ef, out.open("rb") as pf:
        enc_head = ef.read(64)
        plain_head = pf.read(64)
    expected = bytes(a ^ b for a, b in zip(enc_head, plain_head))
    if len(expected) != 64:
        raise RuntimeError("need first 64 bytes")

    unknowns: dict[int, z3.BitVecRef] = {pos: z3.BitVec(f"b{pos}", 8) for pos in missing_positions}
    fek_bytes: list[int | z3.BitVecRef] = []
    for i, b in enumerate(known_fek):
        fek_bytes.append(unknowns[i] if b is None else b)

    state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
    out_words = salsa20_words_z3(state)

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for wi, word in enumerate(out_words[:words_limit]):
        expected_word = int.from_bytes(expected[wi * 4 : wi * 4 + 4], "little")
        solver.add(word == z3.BitVecVal(expected_word, 32))

    status = solver.check()
    if status != z3.sat:
        return {
            "status": str(status),
            "kek": item_kek,
            "encrypted": str(enc),
            "missing_positions": ",".join(map(str, missing_positions)),
            "missing_count": str(len(missing_positions)),
            "words_limit": str(words_limit),
        }

    model = solver.model()
    fek = bytearray(64)
    for i, b in enumerate(known_fek):
        if b is None:
            fek[i] = model.eval(unknowns[i]).as_long()
        else:
            fek[i] = b

    # Verify with local Python Salsa20 implementation.
    if rdt.salsa20_block(bytes(fek)) != expected:
        return {"status": "model_failed_python_verify", "encrypted": str(enc)}

    return {
        "status": "sat",
        "kek": item_kek,
        "encrypted": str(enc),
        "output": str(out),
        "fei_len": str(fei_len),
        "coverage": str(rdt.contiguous(ks)),
        "fek_hex": bytes(fek).hex(),
        "missing_positions": ",".join(map(str, missing_positions)),
        "missing_count": str(len(missing_positions)),
        "words_limit": str(words_limit),
    }


def main() -> int:
    default = SRC_ROOT / "СКЛАД" / "Сканы документов" / "2025" / "2511" / _case_value('586dece1bf9289e9b4e7')
    enc = Path(sys.argv[1]) if len(sys.argv) > 1 else default
    timeout_ms = int(sys.argv[2]) if len(sys.argv) > 2 else 300000
    words_limit = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    row = solve_item(enc, timeout_ms, words_limit)
    report = REPORTS / "z3_tail_fek_attempts.csv"
    exists = report.exists()
    with report.open("a", encoding="utf-8-sig", newline="") as f:
        fields = ["status", "kek", "encrypted", "output", "fei_len", "coverage", "missing_count", "missing_positions", "fek_hex"]
        writer = csv.DictWriter(f, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow({k: row.get(k, "") for k in fields})
    print(row)
    print(f"report={report}")
    return 0 if row.get("status") == "sat" else 2


if __name__ == "__main__":
    raise SystemExit(main())
