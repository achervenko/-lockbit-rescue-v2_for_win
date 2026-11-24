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


def load_seed(kek: str) -> dict[int, int]:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    group = data["groups"][kek]
    return {int(k): int(v, 16) for k, v in group["ks"].items()}


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


def solve_target(item: lr.EncryptedFile, ks: dict[int, int], template: bytes, timeout_ms: int):
    enc = Path(item.path)
    fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
    start = fei_len - 64
    missing = [off for off in range(start, fei_len) if off not in ks]
    enc_prefix = enc.read_bytes()[: len(template)]
    if len(enc_prefix) != len(template):
        return None
    expected = bytes(a ^ b for a, b in zip(enc_prefix, template))
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
    for idx, val in enumerate(expected[:64]):
        solver.add(byte_from_word(words[idx // 4], idx) == z3.BitVecVal(val, 8))
    status = solver.check()
    if status != z3.sat:
        return {"status": str(status), "missing": missing}
    model = solver.model()
    vals = {off: model.eval(var, model_completion=True).as_long() for off, var in unknown.items()}
    fek = bytearray(64)
    for i in range(64):
        off = start + i
        ksb = ks[off] if off in ks else vals[off]
        fek[i] = fei_ct[off] ^ ksb
    if rdt.salsa20_block(bytes(fek))[:64] != expected[:64]:
        return {"status": "sat_bad_verify", "missing": missing}
    return {"status": "sat", "missing": missing, "ks_vals": vals, "fek_hex": bytes(fek).hex(), "body_end": body_end}


def candidate_targets(kek: str, files: list[lr.EncryptedFile], ks: dict[int, int], max_gap: int, limit: int):
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
            rows.append((gap, -body_end, item.fei_len, item.original_name.lower(), item))
    rows.sort()
    return [row[-1] for row in rows[:limit]]


def try_decrypt(item: lr.EncryptedFile, fek_hex: str) -> tuple[bool, str]:
    out = output_path_for(item)
    with tempfile.TemporaryDirectory(prefix="z3_pdf_prefix_") as td:
        tmp = Path(td) / _case_value('10e4dbcec46ccafd53be')
        before, after, skipped = 3, 3, 0x520000
        ok = rdt.direct_decrypt_with_timeout(rdt.REPO / "direct-decrypt.exe", Path(item.path), tmp, fek_hex, before, after, hex(skipped))
        if ok and rdt.validate_recovered(tmp, "pdf"):
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tmp, out)
            return True, "FEI_PARAMS_3_3_520000"
        if rdt.try_alternative_chunk_params(item, fek_hex, "pdf", out):
            return True, "ALT_CHUNKING"
    return False, "decrypt_or_validate_failed"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--kek", required=True)
    parser.add_argument("--max-gap", type=int, default=12)
    parser.add_argument("--targets", type=int, default=3)
    parser.add_argument("--prefix-len", type=int, default=64)
    parser.add_argument("--templates", type=int, default=3)
    parser.add_argument("--timeout-ms", type=int, default=300_000)
    args = parser.parse_args()

    ks = load_seed(args.kek)
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [rdt.EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups[args.kek]
    templates = load_prefix_templates(args.kek, args.prefix_len, args.templates)
    targets = candidate_targets(args.kek, files, ks, args.max_gap, args.targets)
    print(f"kek={args.kek} seed_cov={rdt.contiguous(ks)} templates={len(templates)} targets={len(targets)}")
    out_rows = []
    for item in targets:
        print(f"TARGET fei={item.fei_len} gap={max(0, item.fei_len-rdt.contiguous(ks))} {item.original_name}")
        for idx, tpl in enumerate(templates, 1):
            print(f"  template={idx} len={len(tpl)}", flush=True)
            res = solve_target(item, ks, tpl, args.timeout_ms)
            if not res:
                continue
            row = {
                "kek": args.kek,
                "target": str(Path(item.path).relative_to(SRC_ROOT)),
                "fei_len": item.fei_len,
                "template": idx,
                "status": res["status"],
                "missing": ",".join(map(str, res["missing"])),
                "fek_hex": res.get("fek_hex", ""),
                "decrypt": "",
            }
            print(f"    status={res['status']} missing={row['missing']}")
            if res["status"] == "sat":
                ok, reason = try_decrypt(item, res["fek_hex"])
                row["decrypt"] = reason
                print(f"    decrypt={ok} {reason}")
                if ok:
                    out_rows.append(row)
                    report = REPORTS / "pdf_oracles" / "target_groups" / f"z3_pdf_prefix_attack_{args.kek}.csv"
                    write_report(report, out_rows)
                    print(f"FOUND_AND_SAVED {output_path_for(item)}")
                    return 0
            out_rows.append(row)
    report = REPORTS / "pdf_oracles" / "target_groups" / f"z3_pdf_prefix_attack_{args.kek}.csv"
    write_report(report, out_rows)
    print(f"report={report}")
    return 2


def write_report(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    raise SystemExit(main())
