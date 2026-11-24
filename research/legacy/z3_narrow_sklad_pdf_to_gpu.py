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
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

import z3

sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    bit = 8 * (idx % 4)
    return z3.Extract(bit + 7, bit, word)


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def pdf_templates(prefix_len: int, limit: int) -> list[bytes]:
    counter: Counter[bytes] = Counter()
    for path in DST_ROOT.rglob("*.pdf"):
        if "_technical_reports" in path.parts:
            continue
        try:
            data = path.read_bytes()[:prefix_len]
        except OSError:
            continue
        if len(data) == prefix_len and data.startswith(b"%PDF-"):
            counter[data] += 1
    templates = [tpl for tpl, _ in counter.most_common(limit)]
    # Always keep generic producer-agnostic headers in front as fallback.
    generic = [
        b"%PDF-1.4",
        b"%PDF-1.5",
        b"%PDF-1.6",
        b"%PDF-1.7",
    ]
    out: list[bytes] = []
    for g in generic:
        if len(g) <= prefix_len:
            # Pad with common whitespace/object beginnings only when requested.
            out.append(g + b"\n" + b" " * max(0, prefix_len - len(g) - 1))
    for tpl in templates:
        if tpl not in out:
            out.append(tpl)
    return out[:limit]


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    base = rdt.run_dump_ks(max(files, key=lambda f: f.coverage))
    if not base:
        return {}
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    # Learn anything already recoverable from exact outputs/pairs.
    for _ in range(6):
        learned = 0
        for item in sorted(files, key=lambda x: (x.fei_len, x.original_name.lower())):
            out = output_path_for(item)
            if not out.exists():
                continue
            try:
                _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
                if out.stat().st_size != body_end:
                    continue
            except Exception:
                continue
            fek = rdt.recover_fek_from_known_pair(item, ks)
            if fek:
                learned += rdt.learn_fek(ks, item, fek)
        if learned == 0:
            break
    return ks


def candidate_targets(files: list[lr.EncryptedFile], ks: dict[int, int], max_gap: int, limit: int) -> list[lr.EncryptedFile]:
    cov = rdt.contiguous(ks)
    rows = []
    for item in files:
        out = output_path_for(item)
        if out.exists():
            continue
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        gap = max(0, item.fei_len - cov)
        if gap <= max_gap:
            try:
                _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
            except Exception:
                body_end = 0
            rows.append((gap, item.fei_len, body_end, item.original_name.lower(), item))
    rows.sort()
    return [row[-1] for row in rows[:limit]]


def build_solver(item: lr.EncryptedFile, ks: dict[int, int], template: bytes, timeout_ms: int):
    enc = Path(item.path)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
    enc_prefix = enc.read_bytes()[: min(len(template), body_end)]
    if len(enc_prefix) != len(template):
        return None
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
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for idx, plain in enumerate(template):
        solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(enc_prefix[idx] ^ plain, 8))
    return solver, unknown, missing, fei_len, body_end


def uniqueness_probe(solver: z3.Solver, unknown: dict[int, z3.BitVecRef], missing: list[int], domain_samples: int) -> tuple[dict[int, int], dict[int, set[int]], str]:
    status = solver.check()
    if status != z3.sat:
        return {}, {}, str(status)
    model = solver.model()
    fixed: dict[int, int] = {}
    domains: dict[int, set[int]] = {}
    for off in missing:
        var = unknown[off]
        val = model.eval(var, model_completion=True).as_long()
        solver.push()
        solver.add(var != z3.BitVecVal(val, 8))
        alt = solver.check()
        solver.pop()
        if alt == z3.unsat:
            fixed[off] = val
            domains[off] = {val}
            continue
        # Lightweight model enumeration for small-domain hints.
        seen = {val}
        solver.push()
        for _ in range(max(0, domain_samples - 1)):
            solver.add(z3.Or([unknown[o] != z3.BitVecVal(model.eval(unknown[o], model_completion=True).as_long(), 8) for o in missing]))
            st = solver.check()
            if st != z3.sat:
                break
            model = solver.model()
            seen.add(model.eval(var, model_completion=True).as_long())
            if len(seen) >= domain_samples:
                break
        solver.pop()
        domains[off] = seen
    return fixed, domains, "sat"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kek", action="append", required=True)
    parser.add_argument("--max-gap", type=int, default=13)
    parser.add_argument("--targets", type=int, default=3)
    parser.add_argument("--prefix-len", type=int, default=12)
    parser.add_argument("--templates", type=int, default=12)
    parser.add_argument("--timeout-ms", type=int, default=60_000)
    parser.add_argument("--domain-samples", type=int, default=8)
    args = parser.parse_args()

    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    templates = pdf_templates(args.prefix_len, args.templates)
    rows: list[dict[str, str]] = []

    for kek in args.kek:
        files = groups.get(kek, [])
        if not files:
            print(f"kek={kek} not_found")
            continue
        ks = build_group_ks(files)
        cov = rdt.contiguous(ks)
        targets = candidate_targets(files, ks, args.max_gap, args.targets)
        print(f"kek={kek} cov={cov} targets={len(targets)}")
        for item in targets:
            for tpl_idx, tpl in enumerate(templates, 1):
                built = build_solver(item, ks, tpl, args.timeout_ms)
                if not built:
                    continue
                solver, unknown, missing, fei_len, body_end = built
                fixed, domains, status = uniqueness_probe(solver, unknown, missing, args.domain_samples)
                effective_unknown = len(missing) - len(fixed)
                domain_hint = 1
                for off in missing:
                    domain_hint *= len(domains.get(off, set())) or 256
                row = {
                    "kek": kek,
                    "coverage": str(cov),
                    "file": item.original_name,
                    "relative": str(Path(item.path).relative_to(SRC_ROOT)),
                    "fei_len": str(fei_len),
                    "gap": str(max(0, fei_len - cov)),
                    "missing": ",".join(map(str, missing)),
                    "template_index": str(tpl_idx),
                    "template_hex": tpl.hex(),
                    "status": status,
                    "fixed_count": str(len(fixed)),
                    "fixed": ";".join(f"{off}:{val:02x}" for off, val in sorted(fixed.items())),
                    "effective_unknown_bytes": str(effective_unknown),
                    "domain_sample_product": str(domain_hint),
                    "domains": ";".join(f"{off}:{','.join(f'{v:02x}' for v in sorted(vals))}" for off, vals in sorted(domains.items())),
                }
                rows.append(row)
                print(
                    f"  {item.original_name} tpl={tpl_idx} status={status} "
                    f"gap={row['gap']} fixed={len(fixed)} effective={effective_unknown}",
                    flush=True,
                )
                # If this template already narrowed enough, do not burn time on
                # less likely templates for the same target.
                if status == "sat" and effective_unknown <= 7:
                    break

    report = REPORTS / "sklad_z3_narrow_to_gpu.csv"
    if rows:
        with report.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
