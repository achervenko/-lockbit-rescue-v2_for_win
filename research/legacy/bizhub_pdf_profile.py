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
import re
from collections import Counter, defaultdict
from pathlib import Path


RECOVERED_DIR = Path(_case_value('c9a171a8223bbd620048'))
REPORTS = Path(_case_value('031adf537637d897bb54'))
OUT_PREFIX = "bizhub3320"


ASCII_RE = re.compile(rb"[\x20-\x7e]{4,}")
PDF_TOKEN_RE = re.compile(
    rb"(%PDF-[^\r\n]+|%[^\r\n]*\n|/[A-Za-z][A-Za-z0-9_#-]*[^\r\n<>]*(?:\r?\n)?|"
    rb"\d+\s+\d+\s+obj|endobj|stream\r?\n|endstream|xref|trailer|startxref|%%EOF)"
)


def rel(path: Path) -> str:
    return str(path.relative_to(RECOVERED_DIR))


def printable(blob: bytes, limit: int = 120) -> str:
    text = blob[:limit].decode("latin1", errors="replace")
    return text.replace("\r", "\\r").replace("\n", "\\n")


def first_line(blob: bytes, pattern: bytes) -> bytes | None:
    idx = blob.find(pattern)
    if idx < 0:
        return None
    end = blob.find(b"\n", idx)
    if end < 0:
        end = min(len(blob), idx + 200)
    return blob[idx : end + 1]


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    pdfs = sorted(RECOVERED_DIR.rglob("*.pdf"))
    REPORTS.mkdir(parents=True, exist_ok=True)

    fixed = [Counter() for _ in range(2048)]
    prefix_counter = Counter()
    line_counter = Counter()
    line_examples: dict[bytes, str] = {}
    token_counter = Counter()
    token_examples: dict[bytes, str] = {}
    offset_token_counter: dict[tuple[int, bytes], int] = Counter()
    producer_counter = Counter()
    creator_counter = Counter()
    header_counter = Counter()
    first_obj_counter = Counter()
    stream_offsets = Counter()
    eof_tail_counter = Counter()

    files_rows: list[dict[str, object]] = []

    for path in pdfs:
        data = path.read_bytes()
        r = rel(path)
        for i, b in enumerate(data[:2048]):
            fixed[i][b] += 1
        prefix_counter[data[:256]] += 1
        header_counter[data[:32]] += 1
        eof_tail_counter[data[-128:]] += 1

        first_obj = first_line(data, b"1 0 obj")
        if first_obj:
            first_obj_counter[first_obj[:256]] += 1

        for m in ASCII_RE.finditer(data[:8192]):
            s = m.group(0)
            if any(marker in s for marker in [b"PDF", b"Producer", b"Creator", b"CreationDate", b"ModDate", b"bizhub", b"KONICA", b"Konica", b"Filter", b"Flate", b"DCTDecode", b"XObject", b"Image"]):
                line_counter[s[:240]] += 1
                line_examples.setdefault(s[:240], r)

        for key in [b"/Producer", b"/Creator"]:
            idx = data.find(key)
            if idx >= 0:
                end = data.find(b"\n", idx)
                if end < 0:
                    end = min(len(data), idx + 180)
                val = data[idx:end].strip()[:200]
                if key == b"/Producer":
                    producer_counter[val] += 1
                else:
                    creator_counter[val] += 1

        for m in PDF_TOKEN_RE.finditer(data[:16384]):
            tok = m.group(0)[:200]
            token_counter[tok] += 1
            token_examples.setdefault(tok, r)
            # Group by coarse offset to find reusable fragments not only at zero.
            offset_token_counter[(m.start() // 16 * 16, tok)] += 1

        pos = 0
        while True:
            pos = data.find(b"stream", pos)
            if pos < 0:
                break
            stream_offsets[pos // 16 * 16] += 1
            pos += 6

        files_rows.append(
            {
                "relative_path": r,
                "size": len(data),
                "header": printable(data[:80]),
                "producer": printable(next(iter(producer_counter), b"")) if producer_counter else "",
                "stream_count": data.count(b"stream"),
                "xref_pos": data.find(b"xref"),
                "startxref_pos": data.rfind(b"startxref"),
                "eof_pos": data.rfind(b"%%EOF"),
            }
        )

    stable_rows = []
    total = len(pdfs)
    for i, counter in enumerate(fixed):
        if not counter:
            continue
        value, count = counter.most_common(1)[0]
        frac = count / total
        if frac >= 0.95:
            stable_rows.append(
                {
                    "offset": i,
                    "byte_hex": f"{value:02x}",
                    "byte_chr": chr(value) if 32 <= value <= 126 else "",
                    "count": count,
                    "fraction": f"{frac:.6f}",
                }
            )

    token_rows = []
    for tok, count in token_counter.most_common(300):
        if count < max(3, total // 20):
            break
        token_rows.append({"count": count, "fraction": f"{count/total:.6f}", "token_hex": tok.hex(), "token_text": printable(tok), "example": token_examples.get(tok, "")})

    offset_rows = []
    for (off, tok), count in offset_token_counter.most_common(500):
        if count < max(3, total // 20):
            break
        offset_rows.append({"offset_bucket": off, "count": count, "fraction": f"{count/total:.6f}", "token_hex": tok.hex(), "token_text": printable(tok)})

    line_rows = []
    for s, count in line_counter.most_common(300):
        line_rows.append({"count": count, "fraction": f"{count/total:.6f}", "text": printable(s), "hex": s.hex(), "example": line_examples.get(s, "")})

    summary_rows = [
        {"metric": "pdf_count", "value": total},
        {"metric": "total_size", "value": sum(p.stat().st_size for p in pdfs)},
        {"metric": "stable_prefix_bytes_95pct", "value": len(stable_rows)},
        {"metric": "unique_256_byte_prefixes", "value": len(prefix_counter)},
        {"metric": "unique_headers_32", "value": len(header_counter)},
        {"metric": "unique_tail_128", "value": len(eof_tail_counter)},
    ]

    producer_rows = [{"count": c, "fraction": f"{c/total:.6f}", "text": printable(v), "hex": v.hex()} for v, c in producer_counter.most_common()]
    creator_rows = [{"count": c, "fraction": f"{c/total:.6f}", "text": printable(v), "hex": v.hex()} for v, c in creator_counter.most_common()]
    stream_rows = [{"offset_bucket": off, "count": c, "fraction": f"{c/total:.6f}"} for off, c in stream_offsets.most_common(200)]

    write_csv(REPORTS / f"{OUT_PREFIX}_summary.csv", summary_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_files.csv", files_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_stable_prefix_bytes.csv", stable_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_tokens.csv", token_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_offset_tokens.csv", offset_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_strings.csv", line_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_producer.csv", producer_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_creator.csv", creator_rows)
    write_csv(REPORTS / f"{OUT_PREFIX}_stream_offsets.csv", stream_rows)

    md = REPORTS / f"{OUT_PREFIX}_PROFILE_RU.md"
    lines = [
        "# PDF-профиль bizhub3320",
        "",
        f"Источник: `{RECOVERED_DIR}`",
        f"PDF файлов: `{total}`",
        f"Объём: `{sum(p.stat().st_size for p in pdfs)}` байт",
        "",
        "## Что можно использовать как known plaintext",
        "",
        f"- Стабильных байтов в первых 2048 байтах с частотой >=95%: `{len(stable_rows)}`.",
        f"- Уникальных первых 256 байт: `{len(prefix_counter)}`.",
        "- Самые частые PDF-токены и строки вынесены в CSV рядом с этим файлом.",
        "- Если зашифрованный PDF сделан тем же генератором, эти фрагменты можно использовать как oracle не только на offset 0, но и по типовым PDF-объектам.",
        "",
        "## Файлы отчёта",
        "",
        f"- `{OUT_PREFIX}_stable_prefix_bytes.csv`",
        f"- `{OUT_PREFIX}_tokens.csv`",
        f"- `{OUT_PREFIX}_offset_tokens.csv`",
        f"- `{OUT_PREFIX}_strings.csv`",
        f"- `{OUT_PREFIX}_producer.csv`",
        f"- `{OUT_PREFIX}_creator.csv`",
        f"- `{OUT_PREFIX}_stream_offsets.csv`",
    ]
    md.write_text("\n".join(lines), encoding="utf-8")

    print(f"pdfs={total}")
    print(f"stable_prefix_bytes={len(stable_rows)}")
    print(f"out={REPORTS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
