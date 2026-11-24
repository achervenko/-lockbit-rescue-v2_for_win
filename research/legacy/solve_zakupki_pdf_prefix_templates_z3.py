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
from collections import Counter
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
    return z3.Extract(8 * (idx % 4) + 7, 8 * (idx % 4), word)


def pdf_templates(n: int = 32, top: int = 40) -> list[bytes]:
    counter = Counter()
    for p in REC_ROOT.rglob("*.pdf"):
        if "_technical_reports" in p.parts:
            continue
        try:
            data = p.read_bytes()[:n]
        except OSError:
            continue
        if len(data) >= n and data.startswith(b"%PDF-"):
            counter[data] += 1
    # Prefer common templates, but keep uncommon producers too.
    rows = [tpl for tpl, _ in counter.most_common(top)]
    print(f"pdf_template_sources={sum(counter.values())} unique={len(counter)} using={len(rows)}", flush=True)
    return rows


def solve_for_template(item, files, template: bytes, timeout_ms: int) -> str | None:
    ks = build_group_keystream(files)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    start = fei_len - 64
    missing = [off for off in range(start, fei_len) if off not in ks]
    unknown = {off: z3.BitVec(f"ks_{off}", 8) for off in missing}
    fek_bytes = []
    for i in range(64):
        off = start + i
        if off in ks:
            fek_bytes.append(fei_ct[off] ^ ks[off])
        else:
            fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])
    state = [word_from_bytes(fek_bytes[i * 4:i * 4 + 4]) for i in range(16)]
    words = salsa20_words_z3(state)
    enc = Path(item.path).read_bytes()[: min(body_end, len(template))]
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for idx, plain in enumerate(template[:len(enc)]):
        solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(enc[idx] ^ plain, 8))
    status = solver.check()
    if status != z3.sat:
        return None
    model = solver.model()
    learned = dict(ks)
    for off, var in unknown.items():
        learned[off] = model.eval(var).as_long()
    fek = bytes(fei_ct[start + i] ^ learned[start + i] for i in range(64))
    if rdt.salsa20_block(fek)[:len(enc)] != bytes(a ^ b for a, b in zip(enc, template)):
        return None
    return fek.hex()


def try_store(item, fek_hex: str, ks: dict[int, int]) -> bool:
    rel = out_rel_for(Path(item.path))
    before, after, skipped, source = rdt.chunking_params_for(item, ks)
    with tempfile.TemporaryDirectory(prefix="zak_pdf_tpl_") as td:
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
        valid = ok and rdt.validate_recovered(tmp, "pdf")
        print(f"  direct_ok={ok} valid={valid} params={before}/{after}/0x{skipped:x}/{source}", flush=True)
        if not valid:
            return False
        out = OUT_ROOT / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(tmp, out)
        print(f"RECOVERED {out}", flush=True)
        return True


def main() -> int:
    timeout_ms = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    templates = pdf_templates()
    recovered = 0
    for kek, files in groups.items():
        ks = build_group_keystream(files)
        cov = rdt.contiguous(ks)
        targets = []
        for item in files:
            rel = out_rel_for(Path(item.path))
            if rel.suffix.lower() != ".pdf" or (OUT_ROOT / rel).exists():
                continue
            gap = max(0, item.fei_len - cov)
            if gap <= 24:
                targets.append((gap, item))
        for gap, item in sorted(targets, key=lambda x: (x[0], x[1].fei_len)):
            print(f"target gap={gap} fei={item.fei_len} rel={out_rel_for(Path(item.path))}", flush=True)
            for idx, tpl in enumerate(templates, 1):
                fek = solve_for_template(item, files, tpl, timeout_ms)
                if not fek:
                    continue
                print(f"  template_sat index={idx} head={tpl[:32]!r}", flush=True)
                if try_store(item, fek, ks):
                    recovered += 1
                    break
    print(f"recovered={recovered}")
    return 0 if recovered else 2


if __name__ == "__main__":
    raise SystemExit(main())
