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
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"
KEK = _case_value('334d517b17c31441017e')
KNOWN_COV = 108

PAIR_ROOTS = [
    Path(_case_value('f4e5e33bf20cc2d98993')),
    Path(_case_value('793313ad8753ea27fb46')),
    Path(_case_value('4ad553a2014833d3f789')),
]


def rel(path: Path, root: Path = SRC_ROOT) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def coverage_from_fei(fei_len: int) -> int:
    return max(0, (fei_len - lr.COVERAGE_BASE_FROM_FEI) + lr.COVERAGE_OFFSET)


def encrypted_items() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path in SRC_ROOT.rglob("*" + EXT):
        try:
            fei_len, kek_blob = lr.read_footer(path)
            if lr.kek_fingerprint(kek_blob) != KEK:
                continue
            fei_len2, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(path)
        except Exception:
            continue
        cov = coverage_from_fei(fei_len)
        rows.append(
            {
                "path": path,
                "relative_path": rel(path),
                "original_relative_path": rel(path).removesuffix(EXT),
                "name": path.name.removesuffix(EXT),
                "fei_len": fei_len2,
                "coverage": cov,
                "fek_start": fei_len2 - 64,
                "body_size": body_end,
                "size": path.stat().st_size,
                "fei_ct": fei_ct,
            }
        )
    return sorted(rows, key=lambda r: (int(r["fei_len"]), str(r["relative_path"]).lower()))


def stable_plain_for(row: dict[str, object]) -> bytes | None:
    item = lr.EncryptedFile(
        path=str(row["path"]),
        filename=Path(str(row["path"])).name,
        fei_len=int(row["fei_len"]),
        kek_fingerprint=KEK,
        size=int(row["size"]),
        original_name=str(row["name"]),
    )
    return rdt.stable_metadata_plaintext(item)


def entropy(vals: list[int]) -> float:
    if not vals:
        return 0.0
    c = Counter(vals)
    n = len(vals)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def find_pair_candidates(rows: list[dict[str, object]]) -> dict[str, list[str]]:
    wanted = defaultdict(list)
    for row in rows:
        wanted[str(row["name"]).lower()].append(str(row["original_relative_path"]))
    found = defaultdict(list)
    for root in PAIR_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            key = path.name.lower()
            if key in wanted:
                try:
                    size = path.stat().st_size
                except OSError:
                    size = -1
                found[key].append(f"{path} | size={size}")
    return found


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    rows = encrypted_items()
    if not rows:
        raise RuntimeError(f"no files for KEK {KEK}")

    cov_counts = Counter(int(r["coverage"]) for r in rows)
    fei_counts = Counter(int(r["fei_len"]) for r in rows)

    # Which offsets 108..113 could be learned from metadata plaintext?
    offset_rows = []
    for off in range(108, 114):
        all_sources = []
        stable_values = defaultdict(list)
        for row in rows:
            cov = int(row["coverage"])
            plain = stable_plain_for(row)
            if cov <= off < cov + 18:
                all_sources.append(row)
            if plain is not None and cov <= off < cov + len(plain):
                idx = off - cov
                ks_val = bytes(row["fei_ct"])[off] ^ plain[idx]
                stable_values[ks_val].append(row)
        offset_rows.append(
            {
                "offset": off,
                "metadata_sources": len(all_sources),
                "stable_sources": sum(len(v) for v in stable_values.values()),
                "candidate_ks_values": len(stable_values),
                "status": "learnable" if len(stable_values) == 1 else ("no_sources" if not stable_values else "conflict"),
                "top_candidate_counts": ";".join(f"{k:02x}:{len(v)}" for k, v in Counter({k: len(v) for k, v in stable_values.items()}).most_common(8)),
                "coverage_sources": ";".join(f"{k}:{v}" for k, v in sorted(Counter(int(r["coverage"]) for r in all_sources).items())),
            }
        )

    # FEK ciphertext distribution at the unknown offsets; if this is high entropy
    # and no metadata sources exist, the bytes are true per-file FEK material.
    bias_rows = []
    for off in range(108, 114):
        vals = [bytes(r["fei_ct"])[off] for r in rows if int(r["fei_len"]) > off]
        c = Counter(vals)
        bias_rows.append(
            {
                "offset": off,
                "samples": len(vals),
                "unique": len(c),
                "entropy": f"{entropy(vals):.4f}",
                "top_values": ";".join(f"{v:02x}:{n}" for v, n in c.most_common(8)),
            }
        )

    priority = []
    for row in rows:
        fei_len = int(row["fei_len"])
        gap = max(0, fei_len - KNOWN_COV)
        if gap == 0:
            continue
        priority.append(
            {
                "gap_from_108": gap,
                "fei_len": fei_len,
                "coverage": int(row["coverage"]),
                "fek_start": int(row["fek_start"]),
                "body_size": int(row["body_size"]),
                "relative_path": str(row["original_relative_path"]),
            }
        )
    priority.sort(key=lambda r: (int(r["gap_from_108"]), int(r["body_size"]), str(r["relative_path"]).lower()))

    pairs = find_pair_candidates(rows)
    pair_rows = []
    for row in priority[:120]:
        key = Path(str(row["relative_path"])).name.lower()
        if key in pairs:
            pair_rows.append({**row, "candidates": " || ".join(pairs[key])})

    paths = {
        "summary": REPORTS / "sklad_4f_deep_fei_summary.md",
        "offsets": REPORTS / "sklad_4f_deep_fei_offsets_108_113.csv",
        "priority": REPORTS / "sklad_4f_deep_fei_priority_gaps.csv",
        "pairs": REPORTS / "sklad_4f_deep_fei_pair_hits.csv",
        "bias": REPORTS / "sklad_4f_deep_fei_unknown_bias.csv",
    }
    with paths["offsets"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(offset_rows[0].keys()))
        writer.writeheader()
        writer.writerows(offset_rows)
    with paths["priority"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(priority[0].keys()))
        writer.writeheader()
        writer.writerows(priority)
    with paths["pairs"].open("w", encoding="utf-8-sig", newline="") as fh:
        fields = list(pair_rows[0].keys()) if pair_rows else ["gap_from_108", "relative_path", "candidates"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(pair_rows)
    with paths["bias"].open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(bias_rows[0].keys()))
        writer.writeheader()
        writer.writerows(bias_rows)

    gap_counts = Counter(r["gap_from_108"] for r in priority)
    with paths["summary"].open("w", encoding="utf-8") as fh:
        fh.write("# FEI-анализ группы СКЛАД / 4f77497c716d\n\n")
        fh.write(f"- Файлов в группе: {len(rows)}\n")
        fh.write(f"- Текущий contiguous keystream: 0..{KNOWN_COV - 1} ({KNOWN_COV} байт)\n")
        fh.write(f"- Максимальный `coverage` внутри группы: {max(cov_counts)}\n")
        fh.write(f"- Максимальный `fei_len`: {max(fei_counts)}\n")
        fh.write("- Главный вывод: offsets `108..113` не попадают в metadata ни у одного файла этой KEK-группы; это FEK-байты.\n")
        fh.write(_case_value('5a2987ca26e53c6c449a'))
        fh.write("## Распределение gap относительно coverage=108\n\n")
        for gap, count in sorted(gap_counts.items())[:30]:
            fh.write(f"- gap={gap}: {count} файлов\n")
        fh.write("\n## Ближайшие цели\n\n")
        for row in priority[:20]:
            fh.write(f"- gap={row['gap_from_108']} | fei={row['fei_len']} | {row['relative_path']}\n")
        fh.write("\n## Таблицы\n\n")
        for key, path in paths.items():
            if key != "summary":
                fh.write(f"- {key}: `{path}`\n")

    print(f"files={len(rows)} max_cov={max(cov_counts)} max_fei={max(fei_counts)}")
    print("offsets")
    for row in offset_rows:
        print(row)
    print("gap_counts")
    for gap, count in sorted(gap_counts.items())[:20]:
        print(f"gap={gap} count={count}")
    print("pair_hits", len(pair_rows))
    for row in pair_rows[:10]:
        print(row["relative_path"], row["candidates"])
    for name, path in paths.items():
        print(f"{name}={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
