from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


from collections import defaultdict
from datetime import datetime
from pathlib import Path


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
RANSOM_EXT = ".xzg9VRelb"
REPORT_NAME = "НЕ_ВОССТАНОВЛЕНО.txt"


def output_path_for(encrypted_path: Path) -> Path:
    rel = encrypted_path.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(RANSOM_EXT)])


def original_rel_path(encrypted_path: Path) -> Path:
    rel = encrypted_path.relative_to(SRC_ROOT)
    return Path(str(rel)[: -len(RANSOM_EXT)])


def should_skip(encrypted_path: Path) -> bool:
    rel = encrypted_path.relative_to(SRC_ROOT)
    return encrypted_path.name.startswith("ZUP_backup_") or any(
        part.startswith("ZUP.part") for part in rel.parts
    )


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    value = float(size)
    for unit in units:
        if value < 1024 or unit == units[-1]:
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024
    return f"{size} B"


def folder_prefixes(rel_file: Path) -> list[Path]:
    parent = rel_file.parent
    prefixes = [Path(".")]
    if str(parent) == ".":
        return prefixes
    parts = parent.parts
    for i in range(1, len(parts) + 1):
        prefixes.append(Path(*parts[:i]))
    return prefixes


def main() -> int:
    DST_ROOT.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    totals: dict[Path, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "recovered": 0, "remaining": 0, "remaining_bytes": 0}
    )
    remaining_by_folder: dict[Path, list[Path]] = defaultdict(list)

    encrypted_files = [
        p for p in SRC_ROOT.rglob(f"*{RANSOM_EXT}") if not should_skip(p)
    ]

    for encrypted_path in encrypted_files:
        rel_original = original_rel_path(encrypted_path)
        recovered = output_path_for(encrypted_path).exists()
        size = encrypted_path.stat().st_size
        for prefix in folder_prefixes(rel_original):
            totals[prefix]["total"] += 1
            if recovered:
                totals[prefix]["recovered"] += 1
            else:
                totals[prefix]["remaining"] += 1
                totals[prefix]["remaining_bytes"] += size
                remaining_by_folder[prefix].append(encrypted_path)

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    written = 0
    summary_lines = [
        "Сводка по рекурсивным файлам НЕ_ВОССТАНОВЛЕНО.txt",
        f"Обновлено: {now}",
        "",
        "folder | recovered | total | remaining",
    ]

    for rel_folder in sorted(totals, key=lambda p: str(p).lower()):
        stats = totals[rel_folder]
        dst_folder = DST_ROOT if str(rel_folder) == "." else DST_ROOT / rel_folder
        dst_folder.mkdir(parents=True, exist_ok=True)

        display = "." if str(rel_folder) == "." else str(rel_folder)
        remaining = sorted(
            remaining_by_folder.get(rel_folder, []),
            key=lambda p: str(original_rel_path(p)).lower(),
        )

        lines = [
            f"Папка: {display}",
            f"Обновлено: {now}",
            "Сводка считается по этой папке и всем ее подпапкам.",
            f"Восстановлено: {stats['recovered']} / {stats['total']}",
            f"Осталось: {stats['remaining']}",
            f"Осталось по объему: {format_size(stats['remaining_bytes'])}",
            "",
        ]

        if not remaining:
            lines.append("Все файлы из этой папки и ее подпапок восстановлены.")
        else:
            lines.append("Не восстановлено:")
            lines.append("")
            for idx, encrypted_path in enumerate(remaining, 1):
                rel_original = original_rel_path(encrypted_path)
                try:
                    rel_to_folder = rel_original.relative_to(rel_folder)
                except ValueError:
                    rel_to_folder = rel_original
                lines.append(f"{idx}. {rel_to_folder}")
                lines.append(f"   size: {format_size(encrypted_path.stat().st_size)}")

        (dst_folder / REPORT_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
        written += 1
        summary_lines.append(
            f"{display} | {stats['recovered']} | {stats['total']} | {stats['remaining']}"
        )

    summary_path = REPORTS / "recursive_missing_reports_summary.txt"
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(f"written_reports={written}")
    print(f"summary={summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
