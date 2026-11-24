

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
import subprocess
from PIL import Image, ImageStat

ROOT = Path(_case_value('d1a33555b2d14d609464'))
REPORT = Path(_case_value('08ab2799da0e574bf845'))
OUT = Path(_project_path('research/legacy/render_check'))
POPPLER = Path(_case_value('bd90eae183bbf2f8478a'))
CHECK_REPORT = Path(_case_value('a660f366111c1d2d5a6b'))


def is_nonblank(png: Path) -> tuple[bool, float]:
    im = Image.open(png).convert("L")
    stat = ImageStat.Stat(im)
    # White blank pages have tiny standard deviation.
    return stat.stddev[0] > 2.0, stat.stddev[0]


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    with REPORT.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["status"] != "ok":
                continue
            rel = Path(row["file"])
            pdf = ROOT / rel
            pages = int(row["pages"])
            probes = sorted({1, max(1, pages // 2), pages})
            visible = []
            errors = []
            stem = "".join(ch if ch.isalnum() else "_" for ch in str(rel))[:120]
            for page in probes:
                prefix = OUT / f"{stem}_p{page}"
                proc = subprocess.run(
                    [str(POPPLER), "-png", "-f", str(page), "-l", str(page), "-r", "72", str(pdf), str(prefix)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=30,
                )
                png = Path(f"{prefix}-{page}.png")
                if not png.exists():
                    # pdftoppm names a single-page render as prefix-1.png.
                    alt = Path(f"{prefix}-1.png")
                    png = alt if alt.exists() else png
                if png.exists():
                    nonblank, stddev = is_nonblank(png)
                    visible.append(f"{page}:{'nonblank' if nonblank else 'blank'}:{stddev:.2f}")
                if proc.stderr.strip():
                    errors.append(proc.stderr.strip().splitlines()[0][:120])
            rows.append([str(rel), pages, "; ".join(visible), " | ".join(errors[:3])])

    with CHECK_REPORT.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["file", "pages", "probe_pages", "render_warnings"])
        writer.writerows(rows)
    nonblank_docs = sum("nonblank" in row[2] for row in rows)
    print(f"Documents with at least one nonblank probed page: {nonblank_docs}/{len(rows)}")
    print(CHECK_REPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
