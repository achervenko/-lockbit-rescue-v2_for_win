

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import heapq
import os
import sys
import zipfile

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr


REPO = Path(_project_path(''))
ROOT = Path(_case_value('af24f1e46e87927dabaa'))
OUTDIR = Path(_case_value('c39a11347b89083e7f2a'))
TARGETS = [
    Path(_case_value('cee90e64088bc2f7949f')),
    Path(_case_value('529102c9b28c8f0101c5')),
]


def parse_item(path: Path):
    return lr.scan_file_worker((str(path.parent), path.name, [".xzg9VRelb"], lr.DEFAULT_COMMON_EXTS, False))


def valid_xlsx(path: Path):
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        return (
            "[Content_Types].xml" in names
            and "xl/workbook.xml" in names
            and any(name.startswith("xl/worksheets/") for name in names)
        ), len(names), sum(1 for name in names if name.startswith("xl/worksheets/"))


def find_best_oracle(target_kek: str):
    heap = []
    total = 0
    for dirpath, _, files in os.walk(ROOT):
        for fn in files:
            if not fn.endswith(".xzg9VRelb"):
                continue
            base = fn[: -len(".xzg9VRelb")]
            if "." not in base:
                continue
            if base.rsplit(".", 1)[1].lower() not in lr.DEFAULT_COMMON_EXTS:
                continue
            total += 1
            score = len(base)
            path = Path(dirpath) / fn
            if len(heap) < 1000:
                heapq.heappush(heap, (score, str(path)))
            elif score > heap[0][0]:
                heapq.heapreplace(heap, (score, str(path)))

    oracles = []
    for _, spath in sorted(heap, reverse=True):
        path = Path(spath)
        item = parse_item(path)
        if item and item.kek_fingerprint == target_kek:
            oracles.append((path, item))

    print(f"candidates_total={total} same_kek_in_top={len(oracles)}")
    if not oracles:
        return None
    return max(oracles, key=lambda pair: pair[1].coverage)


def main():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    target_items = []
    for target in TARGETS:
        item = parse_item(target)
        print(f"TARGET exists={target.exists()} fei={item.fei_len if item else None} kek={item.kek_fingerprint if item else None} name={item.original_name if item else target.name}")
        if not item:
            raise SystemExit(f"Cannot parse target: {target}")
        target_items.append((target, item))

    target_kek = target_items[0][1].kek_fingerprint
    best = find_best_oracle(target_kek)
    if not best:
        raise SystemExit("No same-KEK oracle found")
    oracle_path, oracle = best
    print(f"BEST_ORACLE fei={oracle.fei_len} coverage={oracle.coverage} name={oracle.original_name} path={oracle_path}")

    _, _, _, oracle_fei, _ = lr.read_fei_ciphertext(oracle_path)
    base_cov = oracle.coverage
    metadata_plain = (
        base_cov.to_bytes(2, "little")
        + (0x520000).to_bytes(8, "little")
        + (3).to_bytes(4, "little")
        + (3).to_bytes(4, "little")
    )
    ks_ext = bytes(oracle_fei[base_cov + i] ^ metadata_plain[i] for i in range(18)).hex()
    effective_coverage = base_cov + 18
    print(f"effective_coverage={effective_coverage} ks_ext={ks_ext}")

    for target, item in target_items:
        gap = max(0, item.fei_len - effective_coverage)
        print(f"\nDECRYPT name={item.original_name} fei={item.fei_len} gap={gap}")
        result = lr.brute_extend_target(
            REPO / "brute-extend.exe",
            target,
            oracle_path,
            oracle.original_name,
            lr.get_magic_for_extension("xlsx"),
            gap,
            3,
            3,
            "0x520000",
            ks_ext,
            timeout=300,
        )
        print(f"BRUTE_STATUS={result.get('STATUS') if result else None}")
        if not result or not result.get("FEK"):
            print("FAILED: no FEK")
            continue

        output = OUTDIR / item.original_name
        if output.exists():
            output.unlink()
        ok = lr.direct_decrypt_file(
            REPO / "direct-decrypt.exe",
            target,
            output,
            lr.hex_clean(result["FEK"]),
            3,
            3,
            "0x520000",
        )
        valid = False
        detail = ""
        if ok:
            try:
                valid, name_count, sheet_count = valid_xlsx(output)
                detail = f"zip_entries={name_count} worksheets={sheet_count}"
            except Exception as exc:
                detail = f"zip_error={type(exc).__name__}:{exc}"
        print(f"OUTPUT={output}")
        print(f"DIRECT_OK={ok} VALID_XLSX={valid} {detail} size={output.stat().st_size if output.exists() else 0}")


if __name__ == "__main__":
    main()
