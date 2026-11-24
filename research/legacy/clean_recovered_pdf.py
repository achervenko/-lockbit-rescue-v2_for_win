

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
import contextlib
import io

from pypdf import PdfReader, PdfWriter

REPORT = Path(_case_value('cf1b85d6a95bc5f2f4b7'))
CLEAN = Path(_case_value('d1a33555b2d14d609464'))
CLEAN_REPORT = Path(_case_value('08ab2799da0e574bf845'))


def main() -> int:
    CLEAN.mkdir(parents=True, exist_ok=True)
    rows = []
    with REPORT.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["status"] != "ok":
                continue
            src = Path(row["output"])
            rel = src.relative_to(Path(_case_value('89c6b6e63bc2d329da38')))
            dest = CLEAN / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    reader = PdfReader(str(src), strict=False)
                    pages = len(reader.pages)
                    sample_text = ""
                    for page in reader.pages[: min(3, pages)]:
                        sample_text += page.extract_text() or ""
                    writer = PdfWriter()
                    for page in reader.pages:
                        writer.add_page(page)
                    with dest.open("wb") as out:
                        writer.write(out)
                    reread = PdfReader(str(dest), strict=False)
                    rows.append([str(rel), str(dest), "ok", len(reread.pages), len(sample_text.strip())])
            except Exception as exc:
                rows.append([str(rel), str(dest), "failed", "", f"{type(exc).__name__}: {exc}"])

    with CLEAN_REPORT.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "output", "status", "pages", "sample_text_chars_or_error"])
        writer.writerows(rows)

    print(f"Cleanly rewritten PDFs: {sum(1 for r in rows if r[2] == 'ok')}/{len(rows)}")
    print(CLEAN_REPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
