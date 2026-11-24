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
import shutil
import sys
import tempfile
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
SRC = SRC_ROOT / "СКЛАД"
DST = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPO = Path(_project_path(''))
EXT = ".xzg9VRelb"
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000
MAX_GAP = int(os.environ.get("RECOVER_MAX_GAP", "2"))
PROGRESS_EVERY = 100
MAX_HELPER_PATH_LEN = 240

EXTRA_MAGIC = {
    # Use container/header prefixes broad enough for real-world variants.
    "jpg": ["ffd8ff"],
    "jpeg": ["ffd8ff"],
    "jfif": ["ffd8ff"],
    "docx": ["504b0304"],
    "xlsx": ["504b0304"],
    "pptx": ["504b0304"],
    "xlsm": ["504b0304"],
    "xlsb": ["504b0304", "d0cf11e0a1b11ae1"],
    "dwg": ["41433130"],
    "lnk": ["4c00000001140200"],
    # SolidWorks files are OLE Compound File Binary in this dataset/family.
    "sldprt": ["d0cf11e0a1b11ae1"],
    "sldasm": ["d0cf11e0a1b11ae1"],
    "slddrw": ["d0cf11e0a1b11ae1"],
    # STEP/STP are text files with a stable ISO-10303 prefix.
    "stp": [_case_value('f27b00682657e9475f46')],
    "step": [_case_value('f27b00682657e9475f46')],
}
lr.MAGIC_DATABASE.update(EXTRA_MAGIC)
SCAN_EXTS = set(lr.DEFAULT_COMMON_EXTS) | set(EXTRA_MAGIC)


@contextmanager
def helper_path(path: str | Path, prefix: str):
    src = Path(path)
    if len(str(src)) < MAX_HELPER_PATH_LEN:
        yield src
        return
    with tempfile.TemporaryDirectory(prefix=f"{prefix}_") as td:
        tmp = Path(td) / src.name[-80:]
        shutil.copy2(src, tmp)
        yield tmp


def parse_out(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def run_dump_ks(item: lr.EncryptedFile) -> bytes | None:
    import subprocess

    arg = "hex:" + item.original_name.encode("utf-8").hex()
    with helper_path(item.path, "oracle") as oracle_path:
        result = subprocess.run(
            [str(REPO / "brute-extend.exe"), "--dump-ks", str(oracle_path), arg],
            capture_output=True,
            text=True,
            timeout=120,
        )
    parsed = parse_out(result.stdout)
    if result.returncode != 0 or parsed.get("STATUS") != "OK_DUMP":
        return None
    return bytes.fromhex(parsed["KS"])


def merge_ks(ks: dict[int, int], offset: int, value: int) -> bool:
    old = ks.get(offset)
    if old is not None and old != value:
        return False
    ks[offset] = value
    return True


def contiguous(ks: dict[int, int]) -> int:
    i = 0
    while i in ks:
        i += 1
    return i


def ks_ext_hex(ks: dict[int, int], base: int, cov: int) -> str:
    if cov <= base:
        return ""
    return bytes(ks[i] for i in range(base, cov)).hex()


def learn_fek(ks: dict[int, int], item: lr.EncryptedFile, fek_hex: str) -> int:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    fek = bytes.fromhex(lr.hex_clean(fek_hex))
    start = fei_len - 64
    learned = 0
    for i, b in enumerate(fek):
        off = start + i
        val = fei_ct[off] ^ b
        existed = off in ks
        if merge_ks(ks, off, val) and not existed:
            learned += 1
    return learned


def output_path_for(item: lr.EncryptedFile) -> Path:
    enc = Path(item.path)
    rel = enc.relative_to(SRC_ROOT)
    rel_no_ext = Path(str(rel)[: -len(EXT)])
    return DST / rel_no_ext


def recover_item(item: lr.EncryptedFile, oracle: lr.EncryptedFile, ks: dict[int, int], base_cov: int) -> tuple[bool, str, int]:
    ext = item.original_name.rsplit(".", 1)[-1].lower() if "." in item.original_name else ""
    magic = lr.get_magic_for_extension(ext)
    if not magic:
        return False, "no_magic", 0

    cov = contiguous(ks)
    gap = max(0, item.fei_len - cov)
    if gap > MAX_GAP:
        return False, f"gap_{gap}", 0

    with helper_path(item.path, "target") as target_path, helper_path(oracle.path, "oracle") as oracle_path:
        result = lr.brute_extend_target(
            REPO / "brute-extend.exe",
            target_path,
            oracle_path,
            oracle.original_name,
            magic,
            gap,
            BEFORE,
            AFTER,
            hex(SKIPPED),
            ks_ext_hex(ks, base_cov, cov),
            timeout=900 if gap >= 3 else 180,
        )
    if not result or not result.get("FEK"):
        return False, f"no_fek_gap_{gap}", 0

    with tempfile.TemporaryDirectory(prefix="recover_tree_") as td:
        tmp = Path(td) / "dec"
        with helper_path(item.path, "direct") as direct_path:
            ok = lr.direct_decrypt_file(
                REPO / "direct-decrypt.exe",
                direct_path,
                tmp,
                lr.hex_clean(result["FEK"]),
                BEFORE,
                AFTER,
                hex(SKIPPED),
            )
        if not ok:
            return False, "direct_failed", 0
        if not lr.validate_decryption_with_magic(tmp, ext):
            return False, "strict_validation_failed", 0
        out = output_path_for(item)
        if not out.exists():
            out.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(tmp, out)

    learned = learn_fek(ks, item, result["FEK"])
    method = "PHASE1_DIRECT" if gap == 0 else f"PHASE2_BRUTE_{gap}"
    return True, method, learned


def main() -> int:
    DST.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(
        SRC, [EXT], SCAN_EXTS, False, 1, lr.DEFAULT_MAX_SIZE, workers=1
    )
    print(f"SCANNED files={scanned} groups={len(groups)} skipped={skipped}", flush=True)

    rows: list[dict[str, str]] = []
    totals = Counter()

    for batch_no, (kek, files) in enumerate(sorted(groups.items(), key=lambda kv: len(kv[1]), reverse=True), 1):
        files = sorted(files, key=lambda f: (f.fei_len, f.original_name.lower()))
        oracle = max(files, key=lambda f: f.coverage)
        base_cov = oracle.coverage
        ks: dict[int, int] = {}

        name_ks = run_dump_ks(oracle)
        if not name_ks:
            print(f"BATCH {batch_no}/{len(groups)} {kek}: cannot dump oracle ks", flush=True)
            continue
        for off, val in enumerate(name_ks):
            ks[off] = val

        name_dumps = 1
        name_learned = 0
        name_conflicts = 0
        for name_item in sorted(files, key=lambda f: f.coverage, reverse=True):
            if name_item.path == oracle.path:
                continue
            try:
                more_ks = run_dump_ks(name_item)
            except Exception:
                continue
            if more_ks is None:
                continue
            name_dumps += 1
            for off, val in enumerate(more_ks):
                existed = off in ks
                if merge_ks(ks, off, val):
                    if not existed:
                        name_learned += 1
                else:
                    name_conflicts += 1

        # Deterministic FEI metadata observed in the same ransomware family:
        # [compressed filename len u16][skipped u64][before u32][after u32].
        try:
            _, _, _, oracle_fei, _ = lr.read_fei_ciphertext(Path(oracle.path))
            metadata = (
                base_cov.to_bytes(2, "little")
                + SKIPPED.to_bytes(8, "little")
                + BEFORE.to_bytes(4, "little")
                + AFTER.to_bytes(4, "little")
            )
            for i, plain in enumerate(metadata):
                merge_ks(ks, base_cov + i, oracle_fei[base_cov + i] ^ plain)
        except Exception:
            pass

        print(
            f"BATCH {batch_no}/{len(groups)} kek={kek} count={len(files)} oracle_fei={oracle.fei_len} "
            f"base_cov={base_cov} start_cov={contiguous(ks)} name_dumps={name_dumps} "
            f"name_learned={name_learned} name_conflicts={name_conflicts} oracle='{oracle.original_name}'",
            flush=True,
        )

        existing_in_batch = 0
        for item in files:
            out = output_path_for(item)
            if out.exists():
                existing_in_batch += 1
                rows.append({
                    "status": "SUCCESS",
                    "method": "SKIPPED_EXISTS",
                    "kek": kek,
                    "fei_len": str(item.fei_len),
                    "encrypted_path": item.path,
                    "output_path": str(out),
                })
        if existing_in_batch:
            print(f"  resume: already_have={existing_in_batch}", flush=True)

        recovered_in_batch = 0
        learned_existing_in_batch = 0
        learned_existing: set[str] = set()
        failed_attempts: set[str] = set()

        rebuild_progress = True
        while rebuild_progress:
            rebuild_progress = False
            for item in files:
                if item.path in learned_existing or item.path in failed_attempts:
                    continue
                if not output_path_for(item).exists():
                    continue
                ok, reason, learned = recover_item(item, oracle, ks, base_cov)
                if ok:
                    learned_existing.add(item.path)
                    learned_existing_in_batch += 1
                    rebuild_progress = True
                    if learned_existing_in_batch % PROGRESS_EVERY == 0:
                        print(
                            f"  progress learned_existing={learned_existing_in_batch} cov={contiguous(ks)}",
                            flush=True,
                        )
                elif not reason.startswith("gap_"):
                    failed_attempts.add(item.path)

        progressed = True
        while progressed:
            progressed = False
            for item in files:
                out = output_path_for(item)
                existed_before = out.exists()
                if existed_before and item.path in learned_existing:
                    continue
                if item.path in failed_attempts:
                    continue
                ok, reason, learned = recover_item(item, oracle, ks, base_cov)
                if ok:
                    if existed_before:
                        learned_existing.add(item.path)
                        learned_existing_in_batch += 1
                    else:
                        recovered_in_batch += 1
                        totals["ok"] += 1
                    progressed = True
                    if not existed_before and recovered_in_batch % PROGRESS_EVERY == 0:
                        print(
                            f"  progress recovered_new={recovered_in_batch} cov={contiguous(ks)} "
                            f"last_fei={item.fei_len}",
                            flush=True,
                        )
                    if existed_before and learned_existing_in_batch % PROGRESS_EVERY == 0:
                        print(
                            f"  progress learned_existing={learned_existing_in_batch} cov={contiguous(ks)}",
                            flush=True,
                        )
                    if not existed_before:
                        rows.append({
                            "status": "SUCCESS",
                            "method": reason,
                            "kek": kek,
                            "fei_len": str(item.fei_len),
                            "encrypted_path": item.path,
                            "output_path": str(output_path_for(item)),
                        })
                elif reason.startswith("gap_"):
                    continue
                else:
                    failed_attempts.add(item.path)

        remaining = sum(1 for item in files if not output_path_for(item).exists())
        for item in files:
            if output_path_for(item).exists():
                continue
            gap = max(0, item.fei_len - contiguous(ks))
            rows.append({
                "status": "FAILED",
                "method": f"NOT_RECOVERED_GAP_{gap}",
                "kek": kek,
                "fei_len": str(item.fei_len),
                "encrypted_path": item.path,
                "output_path": str(output_path_for(item)),
            })
        print(
            f"BATCH_DONE kek={kek} recovered={recovered_in_batch} learned_existing={learned_existing_in_batch} "
            f"remaining={remaining} final_cov={contiguous(ks)}",
            flush=True,
        )

    manifest = DST / "_technical_reports" / "recovery_manifest_sklad.csv"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with manifest.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["status", "method", "kek", "fei_len", "encrypted_path", "output_path"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"DONE ok={totals['ok']} manifest={manifest}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
