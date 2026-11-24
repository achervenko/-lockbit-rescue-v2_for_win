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
SRC_PROFILE = REPORTS / "pdf_oracles" / "target_groups"
OUTDIR = Path(_case_value('4c7821fa55dbec63ba0c'))
ZIP = Path(_case_value('aeda87700e0fd492e354'))


README = """# PDF profile attack package

Цель: бить нужные складские PDF-группы не только через generic `%PDF-`, а через профиль конкретных восстановленных PDF той же KEK-группы.

Что внутри:

- `target_groups/` — профили PDF по KEK:
  - `624dca208326`: 114 восстановленных PDF, ближайший gap 11.
  - `d69d6c669cee`: 14 восстановленных PDF, ближайший gap 12.
  - `df7b34a66dc1`: 54 восстановленных PDF, ближайший gap 22.
- `z3_seeded_pdf_prefix_attack.py` — Z3-атака по полному PDF prefix template.
- `target_group_pdf_profile.py` — перестроение профиля при наличии новых восстановленных файлов.
- `sklad_z3_keystream_seed.json` — актуальный seed coverage.

Важное наблюдение:

Для `624dca208326` первые 64/128 байт совпадают у 114/114 восстановленных PDF:

`%PDF-1.4\\n%...\\r\\n5 0 obj\\n<<\\n/Type /XObject\\n/Subtype /Image\\n/Name /Im0\\n/Width 2480\\n/Height 3507...`

То есть это сильный known plaintext именно нужной группы.

Проверенный локальный результат на ноуте:

- `prefix_len=64`, nearest gap 11 -> Z3 `unknown` за 120 сек.
- `prefix_len=32`, 3 nearest gap 11 -> Z3 `unknown` за 60 сек каждый.

Это НЕ значит, что профиль бесполезен. Это значит, что обычный Z3 тяжело решает Salsa20 с 11 неизвестными байтами. Направления:

1. Запустить этот же скрипт на ПК с большим timeout.
2. Использовать profile signatures как проверку для GPU/CPU brute.
3. Писать специализированный фильтр Salsa20 под первые 64 байта, вместо универсального Z3.

Пример запуска на ПК:

```powershell
python -u .\\z3_seeded_pdf_prefix_attack.py `
  --kek 624dca208326 `
  --max-gap 11 `
  --targets 3 `
  --prefix-len 64 `
  --templates 1 `
  --timeout-ms 900000
```

Перед запуском проверь в скрипте пути `SRC_ROOT`, `DST_ROOT`, `REPORTS` или адаптируй их под ПК.
"""


def main() -> int:
    if OUTDIR.exists():
        shutil.rmtree(OUTDIR)
    OUTDIR.mkdir(parents=True)
    for name in [
        "z3_seeded_pdf_prefix_attack.py",
        "target_group_pdf_profile.py",
        "z3_seeded_group_tail_strategy.py",
        "solve_tail_fek_z3.py",
        "recover_desktop_tree.py",
    ]:
        shutil.copy2(WORK / name, OUTDIR / name)
    shutil.copy2(REPORTS / "sklad_z3_keystream_seed.json", OUTDIR / "sklad_z3_keystream_seed.json")
    shutil.copytree(SRC_PROFILE, OUTDIR / "target_groups")
    (OUTDIR / "README_PDF_PROFILE_ATTACK_RU.md").write_text(README, encoding="utf-8")
    if ZIP.exists():
        ZIP.unlink()
    with zipfile.ZipFile(ZIP, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in OUTDIR.rglob("*"):
            zf.write(path, path.relative_to(OUTDIR))
    print(ZIP)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
