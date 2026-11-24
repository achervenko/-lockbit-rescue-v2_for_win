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
import os
import subprocess
import sys
from pathlib import Path

import z3

sys.path.insert(0, _project_path('research/legacy'))
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as r
from solve_tail_fek_z3 import salsa20_words_z3, word_from_bytes

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

KEK = _case_value('470c09be6dc8eafece66')
REPORT = r.REPORTS / "scan_b71e_shared_ks_z3.csv"


def rel_no_ext(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(r.SRC_ROOT)
    return Path(str(rel)[: -len(r.EXT)])


def build_base_ks(files: list[lr.EncryptedFile]) -> tuple[dict[int, int], lr.EncryptedFile, int]:
    oracle = max(files, key=lambda f: f.coverage)
    name_ks = r.run_dump_ks(oracle)
    if not name_ks:
        raise RuntimeError("cannot dump oracle filename keystream")
    ks = {i: b for i, b in enumerate(name_ks)}
    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        more = r.run_dump_ks(item)
        if not more:
            continue
        for off, val in enumerate(more):
            r.merge_ks(ks, off, val)
    r.learn_name_len_metadata(ks, files)
    r.learn_stable_metadata_profiles(ks, files)
    return ks, oracle, oracle.coverage


def output_is_exact_pair(item: lr.EncryptedFile) -> bool:
    out = r.output_path_for(item)
    if not out.exists() or out.stat().st_size <= 0:
        return False
    _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
    return out.stat().st_size == body_end and r.validate_recovered(out, r.infer_ext(rel_no_ext(item).name))


def exact_pair_expected_block(item: lr.EncryptedFile) -> bytes | None:
    out = r.output_path_for(item)
    if not output_is_exact_pair(item):
        return None
    with Path(item.path).open("rb") as enc_fh, out.open("rb") as plain_fh:
        enc = enc_fh.read(64)
        plain = plain_fh.read(64)
    if len(enc) != 64 or len(plain) != 64:
        return None
    return bytes(a ^ b for a, b in zip(enc, plain))


def solve_shared(max_unknown_off: int, pair_limit: int, words_limit: int, timeout_ms: int) -> dict[str, str]:
    os.environ["RECOVER_FOLDER"] = "SCAN"
    groups, _, _ = lr.scan_source(r.SRC_ROOT / "SCAN", [r.EXT], r.SCAN_EXTS, True, 1, r.MAX_SIZE_BYTES, workers=1)
    files = groups[KEK]
    ks, _, _ = build_base_ks(files)
    base_cov = r.contiguous(ks)
    unknown_offsets = list(range(base_cov, max_unknown_off + 1))
    unknown_ks = {off: z3.BitVec(f"ks{off}", 8) for off in unknown_offsets}

    pairs = []
    for item in files:
        expected = exact_pair_expected_block(item)
        if expected is None:
            continue
        fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        fek_start = fei_len - 64
        missing = [off for off in range(fek_start, fei_len) if off not in ks]
        if not missing:
            continue
        if min(missing) != base_cov:
            continue
        if max(missing) > max_unknown_off:
            continue
        pairs.append((item, fei_len, fei_ct, expected, missing))

    pairs.sort(key=lambda row: (len(row[4]), row[1], rel_no_ext(row[0]).name.lower()))
    pairs = pairs[:pair_limit]
    if not pairs:
        return {"status": "no_pairs", "base_cov": str(base_cov), "max_unknown_off": str(max_unknown_off)}

    solver = z3.Solver()
    solver.set("timeout", timeout_ms)
    for item, fei_len, fei_ct, expected, missing in pairs:
        fek_start = fei_len - 64
        fek_bytes = []
        for i in range(64):
            off = fek_start + i
            if off in ks:
                fek_bytes.append(fei_ct[off] ^ ks[off])
            else:
                fek_bytes.append(z3.BitVecVal(fei_ct[off], 8) ^ unknown_ks[off])
        state = [word_from_bytes(fek_bytes[i * 4 : i * 4 + 4]) for i in range(16)]
        out_words = salsa20_words_z3(state)
        for wi, word in enumerate(out_words[:words_limit]):
            expected_word = int.from_bytes(expected[wi * 4 : wi * 4 + 4], "little")
            solver.add(word == z3.BitVecVal(expected_word, 32))

    status = solver.check()
    row = {
        "status": str(status),
        "base_cov": str(base_cov),
        "max_unknown_off": str(max_unknown_off),
        "unknown_count": str(len(unknown_offsets)),
        "pairs": str(len(pairs)),
        "words_limit": str(words_limit),
        "timeout_ms": str(timeout_ms),
    }
    if status == z3.sat:
        model = solver.model()
        vals = bytes(model.eval(unknown_ks[off]).as_long() for off in unknown_offsets)
        row["ks_hex"] = vals.hex()
        row["ks_start"] = str(base_cov)
        # Verify by asking the normal recovery helper to use the solved extension.
        target = next(item for item in files if rel_no_ext(item).name == _case_value('6302ea68b5cc271dc1f7'))
        oracle = max(files, key=lambda f: f.coverage)
        before, after, skipped, _ = r.chunking_params_for(target, {**ks, **{off: vals[i] for i, off in enumerate(unknown_offsets)}})
        with r.helper_path(target.path, "target") as target_path, r.helper_path(oracle.path, "oracle") as oracle_path:
            result = lr.brute_extend_target(
                r.REPO / "brute-extend.exe",
                target_path,
                oracle_path,
                oracle.original_name,
                "255044462d",
                0,
                before,
                after,
                hex(skipped),
                r.ks_ext_hex({**ks, **{off: vals[i] for i, off in enumerate(unknown_offsets)}}, oracle.coverage, target.fei_len),
                timeout=60,
            )
        row["upd_verify_status"] = "" if result is None else str(result.get("STATUS", ""))
        row["upd_fek_hex"] = "" if result is None else str(result.get("FEK", ""))
    return row


def main() -> int:
    max_unknown_off = int(sys.argv[1]) if len(sys.argv) > 1 else 98
    pair_limit = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    words_limit = int(sys.argv[3]) if len(sys.argv) > 3 else 2
    timeout_ms = int(sys.argv[4]) if len(sys.argv) > 4 else 120000
    row = solve_shared(max_unknown_off, pair_limit, words_limit, timeout_ms)
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    exists = REPORT.exists()
    fields = [
        "status",
        "base_cov",
        "max_unknown_off",
        "unknown_count",
        "pairs",
        "words_limit",
        "timeout_ms",
        "ks_start",
        "ks_hex",
        "upd_verify_status",
        "upd_fek_hex",
    ]
    with REPORT.open("a", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})
    print(row)
    print(f"REPORT {REPORT}")
    return 0 if row.get("status") == "sat" else 2


if __name__ == "__main__":
    raise SystemExit(main())
