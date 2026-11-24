

# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path

from pathlib import Path
import csv
import sys
from pypdf import PdfReader

SRC = Path(_case_value('4bad8ef42d0c11455450'))
OUT = Path(_case_value('89c6b6e63bc2d329da38'))
REPORT = Path(_case_value('cf1b85d6a95bc5f2f4b7'))

PDF_HEADER = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"


def validate_pdf(path: Path) -> tuple[bool, str]:
    try:
        reader = PdfReader(str(path), strict=False)
        pages = len(reader.pages)
        return pages > 0, f"Pages: {pages}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for src in SRC.rglob("*.xzg9VRelb"):
        rel = src.relative_to(SRC)
        if not src.name.lower().endswith(_case_value('8236c863ae07f5ad86b9')):
            rows.append([str(rel), "", "skipped", "not a PDF-encrypted filename"])
            continue

        data = bytearray(src.read_bytes())
        first_obj = data.find(b" obj")
        xref = data.rfind(b"xref")
        eof = data.rfind(b"%%EOF")
        if xref < 0 or eof < 0 or first_obj < 0:
            rows.append([str(rel), "", "failed", "no plaintext PDF structure found"])
            continue

        data[: len(PDF_HEADER)] = PDF_HEADER
        candidate = bytes(data[: eof + len(b"%%EOF")]) + b"\n"

        out_rel = Path(*rel.parts).with_name(rel.name[:-len(".xzg9VRelb")])
        out_path = OUT / out_rel
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_bytes(candidate)

        ok, info = validate_pdf(out_path)
        status = "ok" if ok else "candidate_failed_pypdf"
        rows.append([str(rel), str(out_path), status, info[:500]])

    with REPORT.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "output", "status", "details"])
        writer.writerows(rows)

    ok_count = sum(1 for row in rows if row[2] == "ok")
    print(f"Recovered candidates readable by pdfinfo: {ok_count}/{len(rows)}")
    print(REPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
