from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import shutil
import zipfile
from pathlib import Path


WORK = Path(_project_path('research/legacy'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
OUTDIR = Path(_case_value('7883d958c1be1daceff1'))
ZIP = Path(_case_value('5d04b98e4cd7de7b58d7'))


README = _case_value('d71d1838e20370f40113')


def main() -> int:
    if OUTDIR.exists():
        shutil.rmtree(OUTDIR)
    OUTDIR.mkdir(parents=True)
    for name in [
        "z3_seeded_group_tail_strategy.py",
        "solve_tail_fek_z3.py",
        "recover_desktop_tree.py",
    ]:
        shutil.copy2(WORK / name, OUTDIR / name)
    shutil.copy2(REPORTS / "sklad_z3_keystream_seed.json", OUTDIR / "sklad_z3_keystream_seed.json")
    (OUTDIR / "README_Z3_SEED_FIX_RU.md").write_text(README, encoding="utf-8")
    if ZIP.exists():
        ZIP.unlink()
    with zipfile.ZipFile(ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in OUTDIR.rglob("*"):
            zf.write(path, path.relative_to(OUTDIR))
    print(ZIP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
