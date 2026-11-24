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
import json
import math
import os
import sys
from collections import Counter
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
SEED = REPORTS / "sklad_z3_keystream_seed.json"
EXT = ".xzg9VRelb"
KEK = _case_value('4906e8c091d91acf1ae1')


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def load_seed() -> dict[int, int]:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    return {int(off): int(byte_hex, 16) for off, byte_hex in data["groups"][KEK]["ks"].items()}


def entropy(counter: Counter[int], total: int) -> float:
    h = 0.0
    for count in counter.values():
        p = count / total
        h -= p * math.log2(p)
    return h


def main() -> int:
    ks = load_seed()
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups[KEK]
    rows = []
    byte_counters = [Counter() for _ in range(64)]
    word_counters = [Counter() for _ in range(16)]

    for item in files:
        out = output_path_for(item)
        if not out.exists() or not out.is_file():
            continue
        try:
            fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        if out.stat().st_size != body_end:
            continue
        start = fei_len - 64
        if start < 0 or any(off not in ks for off in range(start, fei_len)):
            continue
        fek = bytes(fei_ct[start + i] ^ ks[start + i] for i in range(64))
        for i, b in enumerate(fek):
            byte_counters[i][b] += 1
        for wi in range(16):
            word_counters[wi][int.from_bytes(fek[wi * 4 : wi * 4 + 4], "little")] += 1
        rows.append(
            {
                "name": item.original_name,
                "fei_len": fei_len,
                "body_end": body_end,
                "fek_hex": fek.hex(),
                "tail11_hex": fek[53:64].hex(),
                "word13_hex": fek[52:56].hex(),
                "word14_hex": fek[56:60].hex(),
                "word15_hex": fek[60:64].hex(),
            }
        )

    REPORTS.mkdir(parents=True, exist_ok=True)
    csv_path = REPORTS / "analyze_624_fek_patterns_rows.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["name", "fei_len", "body_end", "fek_hex", "tail11_hex", "word13_hex", "word14_hex", "word15_hex"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    md = []
    md.append("# FEK pattern analysis for KEK 624dca208326")
    md.append("")
    md.append(f"Samples with fully known FEK: `{len(rows)}`")
    md.append("")
    md.append("## Byte entropy")
    md.append("")
    md.append("| FEK byte | unique | entropy bits | most common |")
    md.append("|---:|---:|---:|---|")
    for i in range(64):
        c = byte_counters[i]
        total = sum(c.values())
        common = " ".join(f"{b:02x}:{n}" for b, n in c.most_common(5))
        md.append(f"| {i} | {len(c)} | {entropy(c, total) if total else 0:.3f} | `{common}` |")
    md.append("")
    md.append("## Tail words")
    md.append("")
    for wi in (13, 14, 15):
        c = word_counters[wi]
        md.append(f"- word{wi}: unique `{len(c)}` out of `{len(rows)}` samples; top `{', '.join(f'0x{w:08x}:{n}' for w,n in c.most_common(5))}`")
    md.append("")
    md.append("## Conclusion")
    md.append("")
    if rows:
        weak = [i for i, c in enumerate(byte_counters) if len(c) <= max(3, len(rows) // 10)]
        md.append(f"Low-diversity FEK byte positions: `{weak}`")
        md.append(
            "If bytes 53..63 had low diversity or repeated words, we could prioritize/bruteforce a much smaller space. "
            "If they show near-random entropy, pair-based FEK prediction is not promising."
        )
    md_path = REPORTS / "analyze_624_fek_patterns.md"
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(csv_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
