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
from pathlib import Path


REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
PDF_ORACLES = REPORTS / "pdf_oracles"
MANIFEST = REPORTS / "recovery_manifest_склад_latest.csv"
OUT = PDF_ORACLES / "PDF_ORACLE_PROGRESS_RU.md"


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main() -> int:
    manifest = read_csv(MANIFEST)
    new_success = [r for r in manifest if r.get("status") == "SUCCESS" and r.get("method") != "SKIPPED_EXISTS"]
    methods: dict[str, int] = {}
    for row in new_success:
        methods[row["method"]] = methods.get(row["method"], 0) + 1

    lines = [
        "# PDF-oracle / MFP-profile progress",
        "",
        "Дата: 2026-09-14",
        "",
        "## Что сделано",
        "",
        "- Построен профиль восстановленных PDF из `SCAN\\bizhub3320`: 287 PDF, около 93 MB.",
        "- Выделены устойчивые PDF/JPEG/Image-XObject фрагменты, характерные для сканов с МФУ.",
        "- В `recover_desktop_tree.py` добавлены дополнительные PDF-oracle signatures для bizhub/Konica-подобных PDF.",
        "- Найден отдельный класс проблемы: правильный FEK, но неверные chunking параметры крупного PDF.",
        _case_value('12c74bbe7ac8fb8a1291'),
        "- Этот chunking-вариант добавлен в программу как дополнительная альтернатива.",
        "",
        "## Практический результат",
        "",
        f"- Последний складской прогон восстановил новых файлов по manifest: `{len(new_success)}`.",
        _case_value('1b67cc77bedf97599920'),
        "- После этого оставшихся складских PDF с `gap=0` не найдено: очевидный класс `FEK известен, но файл не сохранён` закрыт на текущем наборе.",
        "",
        "## Методы новых восстановлений",
        "",
    ]
    for method, count in sorted(methods.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"- `{method}`: `{count}`")
    lines.extend(
        [
            "",
            "## Артефакты",
            "",
            "- `bizhub3320_PROFILE_RU.md`",
            "- `bizhub3320_tokens.csv`",
            "- `bizhub3320_offset_tokens.csv`",
            "- `bizhub3320_stable_prefix_bytes.csv`",
            _case_value('73f7b2fc2823a5ab3a6d'),
            "- `sklad_remaining_gap0_pdf_candidates.csv`",
            "",
            "## Следующий другой путь",
            "",
            "1. Сделать такой же профиль не только по `bizhub3320`, а по восстановленным складским PDF-группам: 1C/сканы/Konica/Bizhub/прочие генераторы.",
            "2. Автоматически кластеризовать PDF по первым объектам и добавлять только сильные signatures, чтобы не раздувать brute-force.",
            "3. Для файлов с правильным FEK, но bad validation, запускать расширенный chunk sweep и сохранять лучший strict-valid результат.",
            "4. Для ближайших gap-кандидатов использовать PDF signatures как более строгие проверки, чем `%PDF-`, чтобы быстрее подтверждать/отбрасывать FEK.",
            "",
        ]
    )
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
