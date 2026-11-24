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
from collections import Counter, defaultdict
from pathlib import Path


REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
INVENTORY = REPORTS / "sklad_known_feks_after_gpu_chain.csv"
OUTDIR = REPORTS / "fek_prng_research_after_gpu"
TARGET_KEKS = {_case_value('4906e8c091d91acf1ae1'), _case_value('fc3a6afde96d79d41911'), _case_value('5a95466376149ac63974'), _case_value('334d517b17c31441017e')}


def entropy(counter: Counter[int]) -> float:
    total = sum(counter.values())
    if not total:
        return 0.0
    return -sum((count / total) * math.log2(count / total) for count in counter.values())


def hamming(a: bytes, b: bytes) -> int:
    return sum((x ^ y).bit_count() for x, y in zip(a, b))


def load_rows() -> list[dict[str, str]]:
    with INVENTORY.open("r", encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        row["fek"] = bytes.fromhex(row["fek_hex"])
        row["body_size_i"] = int(row.get("body_size") or 0)
        row["fei_len_i"] = int(row.get("fei_len") or 0)
        row["coverage_i"] = int(row.get("coverage") or 0)
    return rows


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def grouped(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    out: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        out[row["kek"]].append(row)
    for vals in out.values():
        vals.sort(key=lambda r: (r.get("rel", ""), r.get("path", "")))
    return out


def position_stats(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    by_kek = grouped(rows)
    scopes = {"ALL": rows}
    scopes.update({k: v for k, v in by_kek.items() if k in TARGET_KEKS or len(v) >= 100})
    out: list[dict[str, object]] = []
    for scope, vals in sorted(scopes.items()):
        for pos in range(64):
            c = Counter(row["fek"][pos] for row in vals)
            value, count = c.most_common(1)[0]
            out.append(
                {
                    "scope": scope,
                    "position": pos,
                    "samples": len(vals),
                    "unique_values": len(c),
                    "top_hex": f"{value:02x}",
                    "top_count": count,
                    "top_fraction": f"{count / len(vals):.6f}",
                    "entropy_bits": f"{entropy(c):.4f}",
                }
            )
    return out


def word_stats(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    by_kek = grouped(rows)
    scopes = {"ALL": rows}
    scopes.update({k: v for k, v in by_kek.items() if k in TARGET_KEKS or len(v) >= 100})
    out: list[dict[str, object]] = []
    for scope, vals in sorted(scopes.items()):
        for word in range(16):
            c = Counter(int.from_bytes(row["fek"][word * 4 : word * 4 + 4], "little") for row in vals)
            value, count = c.most_common(1)[0]
            out.append(
                {
                    "scope": scope,
                    "word": word,
                    "byte_range": f"{word * 4}-{word * 4 + 3}",
                    "samples": len(vals),
                    "unique_values": len(c),
                    "top_hex_le": f"{value:08x}",
                    "top_count": count,
                    "top_fraction": f"{count / len(vals):.6f}",
                    "entropy_bits": f"{entropy(c):.4f}",
                }
            )
    return out


def neighbor_stats(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for kek, vals in grouped(rows).items():
        if len(vals) < 2:
            continue
        for a, b in zip(vals, vals[1:]):
            fx = a["fek"]
            fy = b["fek"]
            tail_xor = int.from_bytes(fx[56:64], "little") ^ int.from_bytes(fy[56:64], "little")
            full_h = hamming(fx, fy)
            tail_h = hamming(fx[56:64], fy[56:64])
            prefix_h = hamming(fx[:56], fy[:56])
            out.append(
                {
                    "kek": kek,
                    "full_hamming_bits": full_h,
                    "prefix56_hamming_bits": prefix_h,
                    "tail8_hamming_bits": tail_h,
                    "tail8_xor_hex": f"{tail_xor:016x}",
                    "same_ext": str(a.get("ext") == b.get("ext")),
                    "a_rel": a.get("rel") or a.get("path"),
                    "b_rel": b.get("rel") or b.get("path"),
                }
            )
    out.sort(key=lambda r: (int(r["full_hamming_bits"]), int(r["tail8_hamming_bits"])))
    return out


def repeated_values(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    chunks = [
        ("fek64", 0, 64),
        ("prefix16", 0, 16),
        ("middle32", 16, 48),
        ("tail16", 48, 64),
        ("tail8", 56, 64),
        ("tail6", 58, 64),
        ("tail4", 60, 64),
    ]
    scopes = {"ALL": rows}
    scopes.update(grouped(rows))
    for scope, vals in scopes.items():
        if len(vals) < 2:
            continue
        for label, start, end in chunks:
            c = Counter(row["fek"][start:end].hex() for row in vals)
            for value, count in c.most_common(20):
                if count < 2:
                    break
                examples = [row.get("rel") or row.get("path") for row in vals if row["fek"][start:end].hex() == value][:5]
                out.append(
                    {
                        "scope": scope,
                        "chunk": label,
                        "range": f"{start}-{end - 1}",
                        "hex": value,
                        "count": count,
                        "examples": " | ".join(examples),
                    }
                )
    out.sort(key=lambda r: (-int(r["count"]), r["scope"], r["chunk"]))
    return out


def adjacent_word_delta_stats(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for kek, vals in grouped(rows).items():
        if len(vals) < 3:
            continue
        counters = [Counter() for _ in range(16)]
        for a, b in zip(vals, vals[1:]):
            for word in range(16):
                x = int.from_bytes(a["fek"][word * 4 : word * 4 + 4], "little")
                y = int.from_bytes(b["fek"][word * 4 : word * 4 + 4], "little")
                counters[word][(y - x) & 0xFFFFFFFF] += 1
        for word, counter in enumerate(counters):
            value, count = counter.most_common(1)[0]
            out.append(
                {
                    "kek": kek,
                    "word": word,
                    "byte_range": f"{word * 4}-{word * 4 + 3}",
                    "pairs": sum(counter.values()),
                    "unique_deltas": len(counter),
                    "top_delta_hex": f"{value:08x}",
                    "top_count": count,
                    "top_fraction": f"{count / sum(counter.values()):.6f}",
                }
            )
    out.sort(key=lambda r: (-float(r["top_fraction"]), r["kek"], int(r["word"])))
    return out


def summary(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for kek, vals in grouped(rows).items():
        tail_uniques = len({row["fek"][56:64] for row in vals})
        full_uniques = len({row["fek"] for row in vals})
        avg_full_h = ""
        if len(vals) > 1:
            hs = [hamming(a["fek"], b["fek"]) for a, b in zip(vals, vals[1:])]
            avg_full_h = f"{sum(hs) / len(hs):.2f}"
        out.append(
            {
                "kek": kek,
                "samples": len(vals),
                "full_fek_unique": full_uniques,
                "tail8_unique": tail_uniques,
                "tail8_repeat_count": len(vals) - tail_uniques,
                "avg_adjacent_hamming": avg_full_h,
                "exts": "; ".join(f"{ext}:{count}" for ext, count in Counter(r.get("ext", "") for r in vals).most_common(8)),
            }
        )
    out.sort(key=lambda r: -int(r["samples"]))
    return out


def main() -> int:
    rows = load_rows()
    OUTDIR.mkdir(parents=True, exist_ok=True)
    write_csv(OUTDIR / "summary_by_kek.csv", summary(rows))
    write_csv(OUTDIR / "byte_position_stats.csv", position_stats(rows))
    write_csv(OUTDIR / "word_position_stats.csv", word_stats(rows))
    write_csv(OUTDIR / "nearest_adjacent_feks.csv", neighbor_stats(rows)[:1000])
    write_csv(OUTDIR / "repeated_chunks.csv", repeated_values(rows))
    write_csv(OUTDIR / "adjacent_word_delta_stats.csv", adjacent_word_delta_stats(rows))
    print(f"input_rows={len(rows)}")
    print(f"outdir={OUTDIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
