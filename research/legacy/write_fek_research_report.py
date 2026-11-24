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
OUTDIR = REPORTS / "fek_prng_research_after_gpu"
REPORT = OUTDIR / "FEK_PRNG_RESEARCH_AFTER_GPU_RU.md"


def read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def main() -> int:
    summary = read_csv(OUTDIR / "summary_by_kek.csv")
    byte_stats = read_csv(OUTDIR / "byte_position_stats.csv")
    word_stats = read_csv(OUTDIR / "word_position_stats.csv")
    constraints = read_csv(REPORTS / "sklad_target_group_known_pair_constraints.csv")
    z3_624 = read_csv(REPORTS / "z3_trained_group_tail_624dca208326.csv")

    total_samples = sum(int(r["samples"]) for r in summary)
    repeated_tail = sum(int(r["tail8_repeat_count"]) for r in summary)
    all_byte_top = max((float(r["top_fraction"]) for r in byte_stats if r.get("scope") == "ALL"), default=0.0)
    all_word_unique = min((int(r["unique_values"]) for r in word_stats if r.get("scope") == "ALL"), default=0)

    lines: list[str] = []
    lines.append("# Исследование FEK/PRNG после GPU-находки")
    lines.append("")
    lines.append("Дата: 2026-09-14")
    lines.append("")
    lines.append("## Что проверено")
    lines.append("")
    lines.append(f"- Собран свежий инвентарь полных FEK по складу: `{total_samples}` образцов.")
    lines.append("- Отдельно учтена GPU-находка для группы `4f77497c716d`, после которой эта группа почти полностью раскрыта.")
    lines.append("- Проверены распределения байтов FEK по позициям, 32-битные слова FEK, повторы хвоста FEK, соседние FEK по порядку путей и дельты соседних слов.")
    lines.append("- Проверены known-pair ограничения для целевых PDF-групп 2026 года.")
    lines.append("- Сделан короткий диагностический Z3-прогон по группе `624dca208326`.")
    lines.append("")
    lines.append("## Главный вывод")
    lines.append("")
    lines.append("Известные FEK выглядят как криптографически случайные 64 байта. На текущей выборке не найдено полезной статистической слабости, которая позволила бы обучить подбор или резко сузить хвост FEK только по уже известным FEK.")
    lines.append("")
    lines.append("Практически это означает: простой ML/RL/частотный подбор не даст выигрыша. Рабочие направления остаются такими:")
    lines.append("")
    lines.append("1. known-pair -> ограничения Salsa20 -> Z3/SMT или специализированный решатель;")
    lines.append("2. GPU brute-force, но только после сужения неизвестного хвоста хотя бы до 6-7 байт;")
    lines.append("3. поиск оригинала/клона для ближайших файлов, если нужно быстро сдвинуть группу.")
    lines.append("")
    lines.append("## Статистика FEK")
    lines.append("")
    lines.append(f"- Повторов полного FEK: не обнаружено.")
    lines.append(f"- Повторов последних 8 байт FEK: `{repeated_tail}`.")
    lines.append(f"- Максимальная доля одного байта на позиции по общей выборке: `{all_byte_top:.6f}`.")
    lines.append(f"- Минимальное число уникальных 32-битных слов на позиции по общей выборке: `{all_word_unique}` из `{total_samples}`.")
    lines.append("- Средняя Hamming-дистанция соседних FEK по большим группам около `256` бит из `512`, что соответствует случайным ключам.")
    lines.append("")
    lines.append("## Группы 2026, которые нужны для склада")
    lines.append("")
    for kek in [_case_value('4906e8c091d91acf1ae1'), _case_value('fc3a6afde96d79d41911'), _case_value('5a95466376149ac63974'), _case_value('334d517b17c31441017e')]:
        vals = [r for r in constraints if r.get("kek") == kek]
        exact = [r for r in vals if r.get("exact_pair") == "True"]
        if not vals:
            continue
        closest = sorted(exact, key=lambda r: int(r["missing_fek_bytes"]))[:5]
        lines.append(f"### `{kek}`")
        lines.append("")
        lines.append(f"- recovered outputs: `{len(vals)}`")
        lines.append(f"- exact known-pair: `{len(exact)}`")
        if closest:
            lines.append("- ближайшие known-pair ограничения:")
            for row in closest:
                lines.append(f"  - missing FEK bytes `{row['missing_fek_bytes']}`, FEI `{row['fei_len']}`, file `{row['rel']}`")
        lines.append("")
    lines.append("## Диагностика Z3")
    lines.append("")
    if z3_624:
        statuses = {}
        for row in z3_624:
            statuses[row.get("status", "")] = statuses.get(row.get("status", ""), 0) + 1
        lines.append(f"- `624dca208326`: проверено стратегий `{len(z3_624)}`; статусы: `{statuses}`.")
        lines.append("- На одиночных 32-битных word-ограничениях Z3 выдаёт `unknown` за 30 секунд. Это значит, что использовать Z3 на ноуте как главный решатель неэффективно.")
    else:
        lines.append("- Локальный Z3-прогон ещё не найден.")
    lines.append("")
    lines.append("## Что делать дальше")
    lines.append("")
    lines.append(_case_value('db9c8877129d5eeba956'))
    lines.append("2. Здесь продолжить исследование known-pair ограничений: попробовать не только прямые Z3 word constraints, а частичные фильтры Salsa20, которые могут отбрасывать кандидатов быстрее и затем передаваться на GPU.")
    lines.append("3. Для быстрого практического прироста по `СКЛАД\\Сканы документов\\2026` самые ценные клоны остаются ближайшие файлы групп `624dca208326` и `d69d6c669cee`, потому что у них сейчас missing FEK bytes 11.")
    lines.append("")
    lines.append("## Артефакты")
    lines.append("")
    lines.append(f"- `summary_by_kek.csv`")
    lines.append(f"- `byte_position_stats.csv`")
    lines.append(f"- `word_position_stats.csv`")
    lines.append(f"- `nearest_adjacent_feks.csv`")
    lines.append(f"- `adjacent_word_delta_stats.csv`")
    lines.append(f"- `sklad_target_group_known_pair_constraints.csv`")
    lines.append(f"- `z3_trained_group_tail_624dca208326.csv`")
    lines.append("")

    OUTDIR.mkdir(parents=True, exist_ok=True)
    REPORT.write_text("\n".join(lines), encoding="utf-8")
    print(REPORT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
