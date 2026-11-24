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
import json
import os
import shutil
import sys
import tempfile
import time
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
SEED = REPORTS / "sklad_z3_keystream_seed.json"
PROFILE = REPORTS / "pdf_oracles" / "target_groups"
OUTDIR = PROFILE / "overnight"


def load_seed(kek: str) -> dict[int, int]:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    return {int(k): int(v, 16) for k, v in data["groups"][kek]["ks"].items()}


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(rdt.EXT)])


def load_prefix_templates(kek: str, prefix_len: int, limit: int) -> list[bytes]:
    rows = []
    path = PROFILE / kek / "prefixes.csv"
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if int(row["prefix_len"]) == prefix_len:
                rows.append(row)
    rows.sort(key=lambda r: (-int(r["count"]), r["hex"]))
    return [bytes.fromhex(row["hex"]) for row in rows[:limit]]


def byte_from_word(word: z3.BitVecRef, idx: int) -> z3.BitVecRef:
    bit = 8 * (idx % 4)
    return z3.Extract(bit + 7, bit, word)


def candidate_targets(kek: str, files: list[lr.EncryptedFile], ks: dict[int, int], max_gap: int, limit: int) -> list[lr.EncryptedFile]:
    cov = rdt.contiguous(ks)
    rows = []
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        if output_path_for(item).exists():
            continue
        try:
            _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            body_end = 0
        gap = max(0, item.fei_len - cov)
        if gap <= max_gap:
            rows.append((gap, item.fei_len, -body_end, item.original_name.lower(), item))
    rows.sort()
    return [row[-1] for row in rows[:limit]]


def build_solver(item: lr.EncryptedFile, ks: dict[int, int], template: bytes, prefix_len: int, timeout_ms: int):
    enc = Path(item.path)
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(enc)
    start = fei_len - 64
    missing = [off for off in range(start, fei_len) if off not in ks]
    enc_prefix = enc.read_bytes()[:prefix_len]
    if len(enc_prefix) != prefix_len or len(template) < prefix_len:
        return None
    expected = bytes(a ^ b for a, b in zip(enc_prefix, template[:prefix_len]))
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
    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for idx, val in enumerate(expected):
        solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(val, 8))
    return solver, unknown, missing, fei_len, fei_ct, expected


def try_decrypt(item: lr.EncryptedFile, fek_hex: str) -> tuple[bool, str]:
    out = output_path_for(item)
    # Try FEI/default-ish params first, then the wider alt list.
    with tempfile.TemporaryDirectory(prefix="overnight_pdf_") as td:
        tmp = Path(td) / _case_value('10e4dbcec46ccafd53be')
        for before, after, skipped, name in [
            (3, 3, 0x520000, "FEI_3_3_520000"),
            (3, 0, 0x200000, "MFP_3_0_200000"),
        ]:
            ok = rdt.direct_decrypt_with_timeout(
                rdt.REPO / "direct-decrypt.exe",
                Path(item.path),
                tmp,
                fek_hex,
                before,
                after,
                hex(skipped),
            )
            if ok and rdt.validate_recovered(tmp, "pdf"):
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, out)
                return True, name
    if rdt.try_alternative_chunk_params(item, fek_hex, "pdf", out):
        return True, "ALT_CHUNKING"
    return False, "validation_failed"


def append_csv(path: Path, row: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    exists = path.exists()
    with path.open("a", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def load_done(path: Path) -> set[tuple[str, str, int, int, int]]:
    done = set()
    if not path.exists():
        return done
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("attempt_done") == "1":
                done.add((row["kek"], row["relative"], int(row["prefix_len"]), int(row["template_idx"]), int(row["model_limit"])))
    return done


def solve_attempt(kek: str, item: lr.EncryptedFile, ks: dict[int, int], template: bytes, prefix_len: int, template_idx: int, timeout_ms: int, model_limit: int, report: Path) -> bool:
    rel = str(Path(item.path).relative_to(SRC_ROOT))[: -len(rdt.EXT)]
    built = build_solver(item, ks, template, prefix_len, timeout_ms)
    if not built:
        return False
    solver, unknown, missing, fei_len, fei_ct, expected = built
    tried_models = 0
    status_text = ""
    t0 = time.time()
    while tried_models < model_limit:
        status = solver.check()
        status_text = str(status)
        if status != z3.sat:
            break
        model = solver.model()
        vals = {off: model.eval(var, model_completion=True).as_long() for off, var in unknown.items()}
        start = fei_len - 64
        fek = bytearray(64)
        for i in range(64):
            off = start + i
            ksb = ks[off] if off in ks else vals[off]
            fek[i] = fei_ct[off] ^ ksb
        tried_models += 1
        block = rdt.salsa20_block(bytes(fek))
        prefix_ok = block[:prefix_len] == expected
        decrypt_ok = False
        decrypt_reason = ""
        if prefix_ok:
            decrypt_ok, decrypt_reason = try_decrypt(item, bytes(fek).hex())
        row = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "attempt_done": "0",
            "kek": kek,
            "relative": rel,
            "fei_len": fei_len,
            "gap": max(0, fei_len - rdt.contiguous(ks)),
            "prefix_len": prefix_len,
            "template_idx": template_idx,
            "model_limit": model_limit,
            "model_no": tried_models,
            "status": status_text,
            "missing": ",".join(map(str, missing)),
            "ks_guess_hex": "".join(f"{vals[off]:02x}" for off in sorted(vals)),
            "prefix_ok": str(prefix_ok),
            "decrypt_ok": str(decrypt_ok),
            "decrypt_reason": decrypt_reason,
            "elapsed_sec": f"{time.time() - t0:.2f}",
        }
        append_csv(report, row)
        if decrypt_ok:
            return True
        solver.add(z3.Or([unknown[off] != z3.BitVecVal(vals[off], 8) for off in sorted(unknown)]))

    append_csv(
        report,
        {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "attempt_done": "1",
            "kek": kek,
            "relative": rel,
            "fei_len": fei_len,
            "gap": max(0, fei_len - rdt.contiguous(ks)),
            "prefix_len": prefix_len,
            "template_idx": template_idx,
            "model_limit": model_limit,
            "model_no": tried_models,
            "status": status_text,
            "missing": ",".join(map(str, missing)),
            "ks_guess_hex": "",
            "prefix_ok": "",
            "decrypt_ok": "False",
            "decrypt_reason": "attempt_exhausted",
            "elapsed_sec": f"{time.time() - t0:.2f}",
        },
    )
    return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=float, default=8)
    parser.add_argument("--timeout-ms", type=int, default=300_000)
    parser.add_argument("--targets", type=int, default=12)
    parser.add_argument("--templates", type=int, default=2)
    parser.add_argument("--model-limit", type=int, default=64)
    parser.add_argument("--report", type=Path, default=OUTDIR / "overnight_pdf_prefix_search.csv")
    args = parser.parse_args()

    deadline = time.time() + args.hours * 3600
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [rdt.EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    done = load_done(args.report)
    plan = [
        (_case_value('4906e8c091d91acf1ae1'), 11, [16, 24, 32, 48, 64]),
        (_case_value('fc3a6afde96d79d41911'), 12, [16, 24, 32, 48, 64]),
        (_case_value('4906e8c091d91acf1ae1'), 13, [16, 24, 32]),
        (_case_value('fc3a6afde96d79d41911'), 13, [16, 24, 32]),
    ]
    print(f"REPORT {args.report}", flush=True)
    print(f"Deadline in {args.hours}h. Stop with Ctrl+C.", flush=True)
    for kek, max_gap, prefix_lengths in plan:
        ks = load_seed(kek)
        files = groups.get(kek, [])
        targets = candidate_targets(kek, files, ks, max_gap, args.targets)
        print(f"KEK {kek} cov={rdt.contiguous(ks)} max_gap={max_gap} targets={len(targets)}", flush=True)
        for prefix_len in prefix_lengths:
            templates = load_prefix_templates(kek, max(prefix_len, 64), args.templates)
            for item in targets:
                rel = str(Path(item.path).relative_to(SRC_ROOT))[: -len(rdt.EXT)]
                for template_idx, tpl in enumerate(templates, 1):
                    if time.time() >= deadline:
                        print("TIME_LIMIT_REACHED", flush=True)
                        return 0
                    key = (kek, rel, prefix_len, template_idx, args.model_limit)
                    if key in done or output_path_for(item).exists():
                        continue
                    print(
                        f"TRY kek={kek} gap={max(0, item.fei_len-rdt.contiguous(ks))} "
                        f"prefix={prefix_len} tpl={template_idx} file={item.original_name}",
                        flush=True,
                    )
                    found = solve_attempt(kek, item, ks, tpl, prefix_len, template_idx, args.timeout_ms, args.model_limit, args.report)
                    done.add(key)
                    if found:
                        print(f"FOUND {output_path_for(item)}", flush=True)
                        # Rebuild targets after a success may make more files reachable.
                        return 0
    print("PLAN_DONE", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
