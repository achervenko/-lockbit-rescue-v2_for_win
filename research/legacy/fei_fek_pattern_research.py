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
import os
import sys
from collections import Counter, defaultdict
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports" / "fei_fek_research"
EXT = ".xzg9VRelb"


def out_for(enc: Path) -> Path:
    return DST_ROOT / Path(str(enc.relative_to(SRC_ROOT))[: -len(EXT)])


def ranges(offsets: list[int]) -> str:
    if not offsets:
        return ""
    offsets = sorted(offsets)
    out = []
    s = p = offsets[0]
    for off in offsets[1:]:
        if off == p + 1:
            p = off
            continue
        out.append(f"{s}" if s == p else f"{s}-{p}")
        s = p = off
    out.append(f"{s}" if s == p else f"{s}-{p}")
    return ",".join(out)


def entropy(counter: Counter[int]) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values())


def ext_of(item: lr.EncryptedFile) -> str:
    return rdt.infer_ext(item.original_name).lower()


def known_fek(item: lr.EncryptedFile, ks: dict[int, int]) -> bytes | None:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    start = fei_len - 64
    if start < 0 or not all(off in ks for off in range(start, fei_len)):
        return None
    return bytes(fei_ct[start + i] ^ ks[start + i] for i in range(64))


def decode_meta(item: lr.EncryptedFile, ks: dict[int, int]) -> tuple[int, int, int, int] | None:
    base = item.coverage
    if not all(off in ks for off in range(base, base + 18)):
        return None
    try:
        _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    except Exception:
        return None
    dec = bytes(fei_ct[base + i] ^ ks[base + i] for i in range(18))
    name_len = int.from_bytes(dec[0:2], "little")
    skipped = int.from_bytes(dec[2:10], "little")
    before = int.from_bytes(dec[10:14], "little")
    after = int.from_bytes(dec[14:18], "little")
    sane = name_len == item.coverage and skipped % 0x20000 == 0 and 0 <= before <= 4096 and 0 <= after <= 4096
    return (name_len, skipped, before, after) if sane else None


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(SRC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    fek_rows = []
    target_rows = []
    pos_counters: dict[str, list[Counter[int]]] = defaultdict(lambda: [Counter() for _ in range(64)])
    word_counters: dict[str, list[Counter[int]]] = defaultdict(lambda: [Counter() for _ in range(16)])
    meta_profiles = Counter()

    for kek, files in sorted(groups.items()):
        ks = build_group_keystream(files)
        cov = rdt.contiguous(ks)
        recovered = [it for it in files if out_for(Path(it.path)).exists()]
        remaining = [it for it in files if not out_for(Path(it.path)).exists()]
        full_feks = 0
        for item in recovered:
            meta = decode_meta(item, ks)
            if meta:
                meta_profiles[(ext_of(item), meta[1], meta[2], meta[3])] += 1
            fek = known_fek(item, ks)
            if fek is None:
                continue
            full_feks += 1
            for i, b in enumerate(fek):
                pos_counters[kek][i][b] += 1
                pos_counters["ALL"][i][b] += 1
            for w in range(16):
                val = int.from_bytes(fek[w * 4:w * 4 + 4], "little")
                word_counters[kek][w][val] += 1
                word_counters["ALL"][w][val] += 1
            fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
            fek_rows.append(
                {
                    "kek": kek,
                    "folder": Path(item.path).relative_to(SRC_ROOT).parts[0],
                    "ext": ext_of(item),
                    "fei_len": fei_len,
                    "coverage": cov,
                    "body_size": body_end,
                    "fek_hex": fek.hex(),
                    "path": item.path,
                }
            )

        for item in remaining:
            fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
            fek_start = fei_len - 64
            known = [off for off in range(fek_start, fei_len) if off in ks]
            missing = [off for off in range(fek_start, fei_len) if off not in ks]
            target_rows.append(
                {
                    "kek": kek,
                    "folder": Path(item.path).relative_to(SRC_ROOT).parts[0],
                    "ext": ext_of(item),
                    "fei_len": fei_len,
                    "coverage": cov,
                    "fek_start": fek_start,
                    "known_fek_bytes": len(known),
                    "missing_fek_bytes": len(missing),
                    "missing_fek_offsets": ranges(missing),
                    "gap_full_fei": max(0, fei_len - cov),
                    "body_size": body_end,
                    "recovered_in_group_with_full_fek": full_feks,
                    "path": item.path,
                }
            )
        print(
            f"kek={kek} files={len(files)} recovered={len(recovered)} remaining={len(remaining)} "
            f"cov={cov} full_feks={full_feks}",
            flush=True,
        )

    pos_rows = []
    for scope, counters in sorted(pos_counters.items()):
        for pos, counter in enumerate(counters):
            total = sum(counter.values())
            if not total:
                continue
            value, count = counter.most_common(1)[0]
            pos_rows.append(
                {
                    "scope": scope,
                    "position": pos,
                    "samples": total,
                    "unique_values": len(counter),
                    "top_value_hex": f"{value:02x}",
                    "top_count": count,
                    "top_fraction": f"{count / total:.6f}",
                    "entropy_bits": f"{entropy(counter):.4f}",
                }
            )

    word_rows = []
    for scope, counters in sorted(word_counters.items()):
        for word, counter in enumerate(counters):
            total = sum(counter.values())
            if not total:
                continue
            value, count = counter.most_common(1)[0]
            word_rows.append(
                {
                    "scope": scope,
                    "word": word,
                    "samples": total,
                    "unique_values": len(counter),
                    "top_value_hex": f"{value:08x}",
                    "top_count": count,
                    "top_fraction": f"{count / total:.6f}",
                    "entropy_bits": f"{entropy(counter):.4f}",
                }
            )

    profile_rows = [
        {"ext": ext, "skipped_hex": hex(skipped_bytes), "before": before, "after": after, "count": count}
        for (ext, skipped_bytes, before, after), count in meta_profiles.most_common()
    ]

    outputs = [
        (REPORTS / "known_feks.csv", fek_rows),
        (REPORTS / "remaining_fek_gaps.csv", target_rows),
        (REPORTS / "fek_byte_position_stats.csv", pos_rows),
        (REPORTS / "fek_word_position_stats.csv", word_rows),
        (REPORTS / "metadata_profiles.csv", profile_rows),
    ]
    for path, rows in outputs:
        if not rows:
            continue
        with path.open("w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)
        print(f"wrote={path}", flush=True)

    actionable = [r for r in target_rows if int(r["missing_fek_bytes"]) <= 24]
    actionable.sort(key=lambda r: (int(r["missing_fek_bytes"]), int(r["gap_full_fei"]), -int(r["body_size"])))
    print("ACTIONABLE_FEI_TARGETS")
    for row in actionable[:40]:
        print(
            f"missing_fek={row['missing_fek_bytes']} gap={row['gap_full_fei']} "
            f"folder={row['folder']} ext={row['ext']} kek={row['kek']} fei={row['fei_len']} "
            f"path={row['path']}"
        )
    print(f"scanned={scanned} skipped={skipped} known_feks={len(fek_rows)} targets={len(target_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
