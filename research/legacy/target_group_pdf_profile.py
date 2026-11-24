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
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports" / "pdf_oracles" / "target_groups"
TARGET_KEKS = [_case_value('4906e8c091d91acf1ae1'), _case_value('fc3a6afde96d79d41911'), _case_value('5a95466376149ac63974')]
PDF_TOKEN_RE = re.compile(
    rb"(%PDF-[^\r\n]+|%[^\r\n]*\n|/[A-Za-z][A-Za-z0-9_#-]*[^\r\n<>]*(?:\r?\n)?|"
    rb"\d+\s+\d+\s+obj|endobj|stream\r?\n|endstream|xref|trailer|startxref|%%EOF)"
)


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(rdt.EXT)])


def printable(blob: bytes, limit: int = 160) -> str:
    text = blob[:limit].decode("latin1", errors="replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def read_exact_pdf_samples(kek: str, files: list[lr.EncryptedFile]) -> list[tuple[lr.EncryptedFile, Path, bytes]]:
    samples = []
    for item in files:
        if rdt.infer_ext(item.original_name).lower() != "pdf":
            continue
        out = output_path_for(item)
        if not out.exists() or not out.is_file():
            continue
        try:
            _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
            if out.stat().st_size != body_end:
                continue
            data = out.read_bytes()
        except Exception:
            continue
        if data.startswith(b"%PDF-"):
            samples.append((item, out, data))
    return samples


def analyze_group(kek: str, files: list[lr.EncryptedFile]) -> dict[str, object]:
    samples = read_exact_pdf_samples(kek, files)
    total = len(samples)
    prefix_counters = {n: Counter() for n in [8, 16, 32, 64, 128, 256]}
    offset_token_counter: Counter[tuple[int, bytes]] = Counter()
    token_examples: dict[tuple[int, bytes], str] = {}
    producer_counter: Counter[bytes] = Counter()
    creator_counter: Counter[bytes] = Counter()
    fixed = [Counter() for _ in range(4096)]
    file_rows: list[dict[str, object]] = []

    for item, out, data in samples:
        rel = str(Path(item.path).relative_to(SRC_ROOT))[: -len(rdt.EXT)]
        for n, counter in prefix_counters.items():
            if len(data) >= n:
                counter[data[:n]] += 1
        for i, b in enumerate(data[:4096]):
            fixed[i][b] += 1
        for key in [b"/Producer", b"/Creator"]:
            idx = data.find(key)
            if idx >= 0:
                end = data.find(b"\n", idx)
                if end < 0:
                    end = min(len(data), idx + 220)
                val = data[idx:end].strip()[:220]
                if key == b"/Producer":
                    producer_counter[val] += 1
                else:
                    creator_counter[val] += 1
        for m in PDF_TOKEN_RE.finditer(data[:32768]):
            tok = m.group(0)[:220]
            # Skip ultra-short common tokens as signatures, but keep object markers.
            if len(tok) < 6 and not tok.endswith(b"obj"):
                continue
            bucket = m.start() // 16 * 16
            offset_token_counter[(bucket, tok)] += 1
            token_examples.setdefault((bucket, tok), rel)
        file_rows.append(
            {
                "kek": kek,
                "relative": rel,
                "size": len(data),
                "header": printable(data[:96]),
                "producer_pos": data.find(b"/Producer"),
                "creator_pos": data.find(b"/Creator"),
                "obj_count": data.count(b" obj"),
                "stream_count": data.count(b"stream"),
                "startxref": data.rfind(b"startxref"),
                "eof": data.rfind(b"%%EOF"),
            }
        )

    stable_rows = []
    for off, counter in enumerate(fixed):
        if not counter or total == 0:
            continue
        val, count = counter.most_common(1)[0]
        frac = count / total
        if frac >= 0.80:
            stable_rows.append(
                {
                    "kek": kek,
                    "offset": off,
                    "byte_hex": f"{val:02x}",
                    "chr": chr(val) if 32 <= val <= 126 else "",
                    "count": count,
                    "fraction": f"{frac:.6f}",
                }
            )

    prefix_rows = []
    for n, counter in prefix_counters.items():
        for blob, count in counter.most_common(20):
            prefix_rows.append(
                {
                    "kek": kek,
                    "prefix_len": n,
                    "count": count,
                    "fraction": f"{count / total:.6f}" if total else "0",
                    "hex": blob.hex(),
                    "text": printable(blob),
                }
            )

    token_rows = []
    min_count = max(2, int(total * 0.20))
    for (bucket, tok), count in offset_token_counter.most_common(800):
        if count < min_count:
            break
        token_rows.append(
            {
                "kek": kek,
                "offset_bucket": bucket,
                "count": count,
                "fraction": f"{count / total:.6f}" if total else "0",
                "magic_spec": f"@{bucket + 32}:{tok.hex()}",
                "token_hex": tok.hex(),
                "token_text": printable(tok),
                "example": token_examples.get((bucket, tok), ""),
            }
        )

    producer_rows = [
        {"kek": kek, "count": c, "fraction": f"{c / total:.6f}" if total else "0", "text": printable(v), "hex": v.hex()}
        for v, c in producer_counter.most_common()
    ]
    creator_rows = [
        {"kek": kek, "count": c, "fraction": f"{c / total:.6f}" if total else "0", "text": printable(v), "hex": v.hex()}
        for v, c in creator_counter.most_common()
    ]

    # Strong signatures: frequent, long enough, offset-aware, not just "%PDF".
    strong = []
    for row in token_rows:
        tok = bytes.fromhex(row["token_hex"])
        frac = float(row["fraction"])
        if len(tok) >= 12 and frac >= 0.30 and not tok.startswith(b"%PDF"):
            strong.append(row)
    strong = strong[:40]

    return {
        "kek": kek,
        "sample_count": total,
        "file_rows": file_rows,
        "stable_rows": stable_rows,
        "prefix_rows": prefix_rows,
        "token_rows": token_rows,
        "producer_rows": producer_rows,
        "creator_rows": creator_rows,
        "strong_signatures": strong,
    }


def remaining_targets(kek: str, files: list[lr.EncryptedFile]) -> list[dict[str, object]]:
    base = rdt.run_dump_ks(max(files, key=lambda f: f.coverage))
    ks = {i: b for i, b in enumerate(base or b"")}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
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
        rows.append(
            {
                "kek": kek,
                "coverage": cov,
                "fei_len": item.fei_len,
                "gap": max(0, item.fei_len - cov),
                "size": body_end,
                "relative": str(Path(item.path).relative_to(SRC_ROOT))[: -len(rdt.EXT)],
            }
        )
    rows.sort(key=lambda r: (int(r["gap"]), -int(r["size"])))
    return rows


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(SRC_ROOT / "СКЛАД", [rdt.EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    all_summary = []
    signature_json = {"format": "pdf-oracle-signatures-v1", "groups": {}}

    for kek in TARGET_KEKS:
        files = groups.get(kek, [])
        if not files:
            continue
        result = analyze_group(kek, files)
        rem = remaining_targets(kek, files)
        prefix = REPORTS / kek
        write_csv(prefix / "files.csv", result["file_rows"])
        write_csv(prefix / "stable_prefix_bytes.csv", result["stable_rows"])
        write_csv(prefix / "prefixes.csv", result["prefix_rows"])
        write_csv(prefix / "offset_tokens.csv", result["token_rows"])
        write_csv(prefix / "producer.csv", result["producer_rows"])
        write_csv(prefix / "creator.csv", result["creator_rows"])
        write_csv(prefix / "strong_signatures.csv", result["strong_signatures"])
        write_csv(prefix / "remaining_pdf_targets.csv", rem)

        signature_json["groups"][kek] = {
            "sample_count": result["sample_count"],
            "signatures": [
                {
                    "magic_spec": row["magic_spec"],
                    "count": row["count"],
                    "fraction": row["fraction"],
                    "text": row["token_text"],
                    "example": row["example"],
                }
                for row in result["strong_signatures"]
            ],
        }
        all_summary.append(
            {
                "kek": kek,
                "samples": result["sample_count"],
                "strong_signatures": len(result["strong_signatures"]),
                "remaining_pdf": len(rem),
                "nearest_gap": rem[0]["gap"] if rem else "",
                "nearest_target": rem[0]["relative"] if rem else "",
            }
        )
        print(
            f"kek={kek} samples={result['sample_count']} strong={len(result['strong_signatures'])} "
            f"remaining_pdf={len(rem)} nearest_gap={rem[0]['gap'] if rem else 'n/a'}"
        )

    write_csv(REPORTS / "target_group_pdf_summary.csv", all_summary)
    (REPORTS / "target_group_pdf_signatures.json").write_text(json.dumps(signature_json, ensure_ascii=False, indent=2), encoding="utf-8")
    md = REPORTS / "TARGET_GROUP_PDF_PROFILE_RU.md"
    lines = [
        "# PDF-профиль целевых KEK-групп склада",
        "",
        f"Сканировано файлов склада: `{scanned}`, skipped: `{skipped}`.",
        "",
        "## Сводка",
        "",
    ]
    for row in all_summary:
        lines.append(
            f"- `{row['kek']}`: samples `{row['samples']}`, strong signatures `{row['strong_signatures']}`, "
            f"remaining PDF `{row['remaining_pdf']}`, nearest gap `{row['nearest_gap']}`."
        )
    lines.extend(
        [
            "",
            "## Что это даёт",
            "",
            "- Это профиль именно нужных групп, а не чужого МФУ.",
            "- `strong_signatures.csv` содержит offset-aware магии вида `@N:<hex>`, которые можно подмешивать в Phase 2 brute как строгие PDF-oracle.",
            "- Если сигнатуры совпадают с генератором оставшихся PDF, шанс подтверждать FEK выше, чем по одному `%PDF-`.",
            "",
            "## Следующий шаг",
            "",
            "Подключить `target_group_pdf_signatures.json` в recovery/brute для выбранных KEK и прогнать только ближайшие gap-кандидаты.",
        ]
    )
    md.write_text("\n".join(lines), encoding="utf-8")
    print(REPORTS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
