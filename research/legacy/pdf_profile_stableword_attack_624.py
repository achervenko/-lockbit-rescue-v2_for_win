from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import argparse
import csv
import os
import sys
from collections import Counter
from pathlib import Path

import z3

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
MFU_DIR = REPORTS / "mfu_profile_624" / "15-09-2026_16-43-23"
EXTRA_MFU_DIRS = [Path(_case_value('8638a43d02f2efe8d202'))]
EXT = ".xzg9VRelb"
KEK = _case_value('4906e8c091d91acf1ae1')


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def ranges(offsets: list[int]) -> str:
    if not offsets:
        return ""
    out: list[str] = []
    start = prev = offsets[0]
    for off in offsets[1:]:
        if off == prev + 1:
            prev = off
            continue
        out.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = off
    out.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(out)


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError("cannot dump base keystream")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def exact_pdf_samples(files: list[lr.EncryptedFile]) -> list[bytes]:
    samples: list[bytes] = []
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        out = output_path_for(item)
        if not out.exists() or not out.is_file():
            continue
        try:
            _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        if out.stat().st_size != body_end:
            continue
        data = out.read_bytes()
        if data.startswith(b"%PDF-"):
            samples.append(data)
    return samples


def load_mfu_pdfs() -> list[bytes]:
    files = [p for p in sorted(MFU_DIR.rglob("*.pdf")) if p.is_file()]
    for extra in EXTRA_MFU_DIRS:
        if extra.exists():
            files.extend(p for p in sorted(extra.rglob("*")) if p.is_file() and p.suffix.lower() == ".pdf")
    out = []
    seen: set[tuple[int, bytes]] = set()
    for p in files:
        data = p.read_bytes()
        key = (len(data), data[:256])
        if key in seen:
            continue
        seen.add(key)
        out.append(data)
    return out


def stable_words(samples: list[bytes], mfu_samples: list[bytes], threshold: float, max_offset: int) -> dict[tuple[int, int], bytes]:
    words: dict[tuple[int, int], bytes] = {}
    total = len(samples)
    for off in range(0, max_offset - 3, 4):
        expected = bytearray()
        ok = True
        for pos in range(off, off + 4):
            vals = [data[pos] for data in samples if len(data) > pos]
            if len(vals) != total:
                ok = False
                break
            byte, count = Counter(vals).most_common(1)[0]
            if count / total < threshold:
                ok = False
                break
            if any(len(mfu) <= pos or mfu[pos] != byte for mfu in mfu_samples):
                ok = False
                break
            expected.append(byte)
        if ok:
            words[(off // 64, (off % 64) // 4)] = bytes(expected)
    return words


def collect_rows(
    files: list[lr.EncryptedFile],
    ks: dict[int, int],
    stable: dict[tuple[int, int], bytes],
    max_gap: int,
    pseudo_limit: int,
    exact_limit: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    cov = rdt.contiguous(ks)
    pseudo: list[tuple[int, int, int, str, dict[str, object]]] = []
    exact: list[tuple[int, int, int, str, dict[str, object]]] = []
    max_read = (max(block for block, _ in stable) + 1) * 64 if stable else 128
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        try:
            fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        start = fei_len - 64
        missing = [off for off in range(start, fei_len) if off not in ks]
        if not missing or min(missing) != cov or len(missing) > max_gap:
            continue
        rel = str(Path(item.path).relative_to(SRC_ROOT))[: -len(EXT)]
        out = output_path_for(item)
        if out.exists() and out.is_file() and out.stat().st_size == body_end:
            enc = Path(item.path).read_bytes()[:max_read]
            plain = out.read_bytes()[:max_read]
            expected_words = {
                key: bytes(a ^ b for a, b in zip(enc[block * 64 + word * 4 : block * 64 + word * 4 + 4], plain[block * 64 + word * 4 : block * 64 + word * 4 + 4]))
                for key in stable
                for block, word in [key]
                if len(enc) >= block * 64 + word * 4 + 4 and len(plain) >= block * 64 + word * 4 + 4
            }
            if expected_words:
                exact.append((len(missing), fei_len, -body_end, rel, {"kind": "exact", "rel": rel, "fei_len": fei_len, "body_end": body_end, "fei_ct": fei_ct, "missing": missing, "expected_words": expected_words}))
            continue
        enc = Path(item.path).read_bytes()[:max_read]
        expected_words = {
            key: bytes(a ^ b for a, b in zip(enc[block * 64 + word * 4 : block * 64 + word * 4 + 4], plain4))
            for key, plain4 in stable.items()
            for block, word in [key]
            if len(enc) >= block * 64 + word * 4 + 4
        }
        if expected_words:
            pseudo.append((len(missing), fei_len, -body_end, rel, {"kind": "pseudo", "rel": rel, "fei_len": fei_len, "body_end": body_end, "fei_ct": fei_ct, "missing": missing, "expected_words": expected_words}))
    exact.sort()
    pseudo.sort()
    return [row[-1] for row in exact[:exact_limit]], [row[-1] for row in pseudo[:pseudo_limit]]


def solve(rows: list[dict[str, object]], ks: dict[int, int], selected_keys: list[tuple[int, int]], timeout_ms: int) -> dict[str, str]:
    unknown_offsets = sorted({off for row in rows for off in row["missing"]})  # type: ignore[index]
    unknown = {off: z3.BitVec(f"ks{off}", 8) for off in unknown_offsets if off not in ks}
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for row in rows:
        fei_len = int(row["fei_len"])
        fei_ct: bytes = row["fei_ct"]  # type: ignore[assignment]
        expected_words: dict[tuple[int, int], bytes] = row["expected_words"]  # type: ignore[assignment]
        start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown[off])
        base_state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
        by_block: dict[int, list[int]] = {}
        for block, word in selected_keys:
            if (block, word) in expected_words:
                by_block.setdefault(block, []).append(word)
        for block, words in by_block.items():
            state = base_state[:]
            state[8] = state[8] + z3.BitVecVal(block, 32)
            out_words = salsa20_words_z3(state)
            for word in words:
                solver.add(out_words[word] == z3.BitVecVal(int.from_bytes(expected_words[(block, word)], "little"), 32))
    status = solver.check()
    result = {
        "status": str(status),
        "rows": str(len(rows)),
        "unknown_bytes": str(len(unknown)),
        "ks_offsets": ranges(sorted(unknown)),
        "selected_words": " ".join(f"{b}:{w}" for b, w in selected_keys),
        "ks_hex": "",
    }
    if status == z3.sat:
        model = solver.model()
        result["ks_hex"] = "".join(f"{model.eval(unknown[off], model_completion=True).as_long():02x}" for off in sorted(unknown))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=float, default=1.0)
    parser.add_argument("--max-offset", type=int, default=4096)
    parser.add_argument("--max-gap", type=int, default=12)
    parser.add_argument("--exact-pairs", type=int, default=4)
    parser.add_argument("--pseudo-pairs", type=int, default=4)
    parser.add_argument("--word-limit", type=int, default=24)
    parser.add_argument("--timeout-ms", type=int, default=60_000)
    parser.add_argument("--out", type=Path, default=REPORTS / "pdf_profile_stableword_624.csv")
    args = parser.parse_args()

    groups, scanned, skipped = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups[KEK]
    print(f"scanned={scanned} skipped={skipped} files={len(files)}", flush=True)
    ks = build_group_ks(files)
    print(f"coverage={rdt.contiguous(ks)} known={len(ks)}", flush=True)
    samples = exact_pdf_samples(files)
    mfu_samples = load_mfu_pdfs()
    stable = stable_words(samples, mfu_samples, args.threshold, args.max_offset)
    print(f"samples={len(samples)} mfu={len(mfu_samples)} stable_words={len(stable)} threshold={args.threshold}", flush=True)
    exact, pseudo = collect_rows(files, ks, stable, args.max_gap, args.pseudo_pairs, args.exact_pairs)
    rows = exact + pseudo
    print(f"exact={len(exact)} pseudo={len(pseudo)} rows={len(rows)}", flush=True)
    for row in rows:
        print(f"  {row['kind']} gap={len(row['missing'])} words={len(row['expected_words'])} fei={row['fei_len']} rel={row['rel']}", flush=True)
    # Prefer low blocks and diverse word indexes; they are cheaper and often more discriminating.
    selected = sorted(stable)[: args.word_limit]
    print("selected=" + " ".join(f"{b}:{w}" for b, w in selected), flush=True)
    row = solve(rows, ks, selected, args.timeout_ms)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(row.keys()))
        writer.writeheader()
        writer.writerow(row)
    print(row, flush=True)
    print(f"report={args.out}", flush=True)
    return 0 if row["status"] == "sat" else 2


if __name__ == "__main__":
    raise SystemExit(main())
