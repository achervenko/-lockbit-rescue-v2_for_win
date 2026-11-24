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
from collections import defaultdict
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "МЕТРОЛОГИЯ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import z3
import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from solve_metro_msg_then_retry import OLE_PREFIX, build_group_keystream, out_rel_for
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


ENC_ROOT = Path(_case_value('1417be6d1995580356a1'))
OUT_ROOT = Path(_case_value('f3c3aa9452e88374e1f9'))
EXT = ".xzg9VRelb"


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    shift = 8 * (idx % 4)
    return z3.Extract(shift + 7, shift, word)


def item_words(item: lr.EncryptedFile, ks: dict[int, int], unknown_ks: dict[int, z3.BitVecRef]) -> tuple[list[z3.BitVecRef], bytes, bytes]:
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
    return salsa20_words_z3(state), Path(item.path).read_bytes()[:64], fei_ct


def derive_fek(item: lr.EncryptedFile, ks: dict[int, int]) -> str:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    start = fei_len - 64
    return bytes(fei_ct[start + i] ^ ks[start + i] for i in range(64)).hex()


def direct_store(item: lr.EncryptedFile, fek_hex: str, ks: dict[int, int]) -> bool:
    rel = out_rel_for(Path(item.path))
    ext = rel.suffix.lower().lstrip(".")
    before, after, skipped, _ = rdt.chunking_params_for(item, ks)
    with tempfile.TemporaryDirectory(prefix="metro_global_") as td:
        tmp = Path(td) / rel.name
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
        valid = ok and rdt.validate_recovered(tmp, ext)
        print(f"TRY_STORE valid={valid} ok={ok} ext={ext} rel={rel}", flush=True)
        if not valid:
            if tmp.exists():
                print(f"  head={tmp.read_bytes()[:32].hex()}", flush=True)
            return False
        out = OUT_ROOT / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
        return True


def main() -> int:
    timeout_ms = int(os.environ.get("METRO_GLOBAL_Z3_TIMEOUT_MS", "600000"))
    groups, scanned, skipped = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    print(f"scanned={scanned} groups={len(groups)} skipped={skipped}", flush=True)
    recovered = 0
    for kek, files in groups.items():
        ks = build_group_keystream(files)
        cov = rdt.contiguous(ks)
        targets = []
        for item in files:
            rel = out_rel_for(Path(item.path))
            if (OUT_ROOT / rel).exists():
                continue
            if rel.suffix.lower() in {".pdf", ".msg"}:
                targets.append(item)
        if not targets:
            continue
        max_missing = max(item.fei_len for item in targets) - 1
        unknown_offsets = list(range(cov, max_missing + 1))
        unknown_ks = {off: z3.BitVec(f"ks_{off}", 8) for off in unknown_offsets}
        print(f"kek={kek} cov={cov} targets={len(targets)} unknown={unknown_offsets}", flush=True)

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        cache = {}
        for item in targets:
            cache[item.path] = item_words(item, ks, unknown_ks)
            words, enc_head, _ = cache[item.path]
            rel = out_rel_for(Path(item.path))
            if rel.suffix.lower() == ".msg":
                for idx, plain in enumerate(OLE_PREFIX):
                    solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(enc_head[idx] ^ plain, 8))
            elif rel.suffix.lower() == ".pdf":
                pdf_prefix = b"%PDF-1."
                for idx, plain in enumerate(pdf_prefix):
                    solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(enc_head[idx] ^ plain, 8))
                digit = byte_from_word(words[7 // 4], 7) ^ z3.BitVecVal(enc_head[7], 8)
                solver.add(z3.Or([digit == z3.BitVecVal(ord(ch), 8) for ch in "234567"]))

        by_cert = defaultdict(list)
        for item in targets:
            rel = out_rel_for(Path(item.path))
            name = rel.name
            if "241960" in name:
                by_cert["241960"].append(item)
            if "241973" in name:
                by_cert["241973"].append(item)
        for cert, items in by_cert.items():
            if len(items) < 2:
                continue
            a, b = items[:2]
            words_a, enc_a, _ = cache[a.path]
            words_b, enc_b, _ = cache[b.path]
            print(f"add_equal_plaintext cert={cert}", flush=True)
            for idx in range(64):
                pa = byte_from_word(words_a[idx // 4], idx) ^ z3.BitVecVal(enc_a[idx], 8)
                pb = byte_from_word(words_b[idx // 4], idx) ^ z3.BitVecVal(enc_b[idx], 8)
                solver.add(pa == pb)

        status = solver.check()
        print(f"z3_status={status}", flush=True)
        if status != z3.sat:
            continue
        model = solver.model()
        learned = dict(ks)
        for off, var in unknown_ks.items():
            learned[off] = model.eval(var).as_long()
        print("learned_tail=" + " ".join(f"{off}:{learned[off]:02x}" for off in unknown_offsets), flush=True)
        for item in sorted(targets, key=lambda x: (x.fei_len, out_rel_for(Path(x.path)).as_posix())):
            start = item.fei_len - 64
            if all(off in learned for off in range(start, item.fei_len)):
                if direct_store(item, derive_fek(item, learned), learned):
                    recovered += 1
    print(f"recovered={recovered}", flush=True)
    return 0 if recovered else 2


if __name__ == "__main__":
    raise SystemExit(main())
