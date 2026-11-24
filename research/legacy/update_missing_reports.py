from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


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


def main() -> int:
    DST_ROOT.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)

    folders: dict[str, list[Path]] = {}
    for encrypted_path in SRC_ROOT.rglob(f"*{RANSOM_EXT}"):
        if should_skip(encrypted_path):
            continue
        rel = encrypted_path.relative_to(SRC_ROOT)
        folder = rel.parts[0] if len(rel.parts) > 1 else "<root>"
        folders.setdefault(folder, []).append(encrypted_path)

    summary_lines = [
        "Сводка по файлам НЕ_ВОССТАНОВЛЕНО.txt",
        f"Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "folder | recovered | total | remaining",
    ]

    for folder in sorted(folders):
        encrypted_files = sorted(folders[folder], key=lambda p: str(original_rel_path(p)).lower())
        remaining = [p for p in encrypted_files if not output_path_for(p).exists()]
        recovered_count = len(encrypted_files) - len(remaining)

        if folder == "<root>":
            report_dir = DST_ROOT
            display_folder = "<root>"
        else:
            report_dir = DST_ROOT / folder
            display_folder = folder
        report_dir.mkdir(parents=True, exist_ok=True)

        lines = [
            f"Папка: {display_folder}",
            f"Обновлено: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Восстановлено: {recovered_count} / {len(encrypted_files)}",
            f"Осталось: {len(remaining)}",
            "",
        ]

        if not remaining:
            lines.append("Все файлы из этой папки восстановлены.")
        else:
            lines.append("Список не восстановленных файлов:")
            lines.append("")
            for idx, encrypted_path in enumerate(remaining, 1):
                rel_original = original_rel_path(encrypted_path)
                size = encrypted_path.stat().st_size
                lines.append(f"{idx}. {rel_original}")
                lines.append(f"   encrypted: {encrypted_path}")
                lines.append(f"   size: {format_size(size)}")

        (report_dir / REPORT_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
        summary_lines.append(
            f"{display_folder} | {recovered_count} | {len(encrypted_files)} | {len(remaining)}"
        )

    summary_path = REPORTS / "missing_reports_summary.txt"
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")
    print(f"updated folders={len(folders)}")
    print(f"summary={summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
