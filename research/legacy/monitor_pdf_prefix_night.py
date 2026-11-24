from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import base64
import csv
import os
import re
import subprocess
import time
from collections import Counter
from pathlib import Path


RECOVERED_B64 = "0JLQvtGB0YHRgtCw0L3QvtCy0LvQtdC90L3Ri9C1INGE0LDQudC70Ys="
PID = 21600


def recovered_root() -> Path:
    name = base64.b64decode(RECOVERED_B64).decode("utf-8")
    return Path.home() / "Desktop" / name


def overnight_dir() -> Path:
    return recovered_root() / "_technical_reports" / "pdf_oracles" / "target_groups" / "overnight"


def newest(pattern: str) -> Path | None:
    paths = sorted(overnight_dir().glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)
    return paths[0] if paths else None


def read_tail(path: Path | None, lines: int = 40) -> list[str]:
    if not path or not path.exists():
        return []
    try:
        data = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    return data[-lines:]


def process_status(pid: int) -> tuple[bool, str]:
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-Command",
            f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | Select-Object Id,CPU,StartTime,ProcessName | ConvertTo-Csv -NoTypeInformation",
        ]
        out = subprocess.check_output(cmd, text=True, encoding="utf-8", errors="replace", stderr=subprocess.DEVNULL)
    except Exception:
        return False, "не удалось проверить процесс"
    rows = list(csv.DictReader(out.splitlines()))
    if not rows:
        return False, "процесс не найден"
    row = rows[0]
    return True, f"PID {row.get('Id')} | CPU {row.get('CPU')} сек | старт {row.get('StartTime')}"


def parse_log(lines: list[str]) -> dict[str, str]:
    info: dict[str, str] = {}
    for line in lines:
        if line.startswith("REPORT "):
            info["report"] = line.removeprefix("REPORT ").strip()
        elif line.startswith("Deadline "):
            info["deadline"] = line.strip()
        elif line.startswith("KEK "):
            info["kek_line"] = line.strip()
        elif line.startswith("TRY "):
            info["try_line"] = line.strip()
    if "try_line" in info:
        line = info["try_line"]
        for key in ["kek", "gap", "prefix", "tpl"]:
            m = re.search(rf"{key}=([^ ]+)", line)
            if m:
                info[key] = m.group(1)
        m = re.search(r"file=(.*)$", line)
        if m:
            info["file"] = m.group(1)
    return info


def csv_summary(path: Path | None) -> dict[str, object]:
    result: dict[str, object] = {"exists": False}
    if not path or not path.exists():
        return result
    try:
        with path.open("r", encoding="utf-8-sig", newline="") as f:
            rows = list(csv.DictReader(f))
    except Exception as exc:
        result["error"] = str(exc)
        return result
    result["exists"] = True
    result["rows"] = len(rows)
    result["done"] = sum(1 for r in rows if r.get("attempt_done") == "1")
    result["models"] = sum(1 for r in rows if r.get("attempt_done") == "0")
    result["status"] = Counter(r.get("status", "") for r in rows if r.get("status"))
    result["decrypt_ok"] = [r for r in rows if r.get("decrypt_ok") == "True"]
    result["last"] = rows[-1] if rows else {}
    return result


def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def bar(label: str, value: str = "") -> None:
    print("=" * 78)
    print(f"{label}{(': ' + value) if value else ''}")
    print("=" * 78)


def main() -> int:
    while True:
        log = newest("night_direct_*.log")
        err = newest("night_direct_*.err.log")
        csv_path = newest("night_direct_*.csv")
        alive, proc = process_status(PID)
        log_lines = read_tail(log, 80)
        err_lines = read_tail(err, 20)
        info = parse_log(log_lines)
        summary = csv_summary(csv_path)

        clear()
        bar("НОЧНОЙ ПОИСК PDF-ПРОФИЛЯ")
        print("Что делает процесс:")
        print("  Ищет недостающие байты FEK/keystream для PDF склада через профиль PDF.")
        print("  Это НЕ обычная расшифровка всех файлов, а экспериментальный Z3-поиск.")
        print()
        print("Состояние процесса:")
        print(f"  {'РАБОТАЕТ' if alive else 'ОСТАНОВЛЕН'} | {proc}")
        print()
        print("Текущая попытка:")
        if "try_line" in info:
            print(f"  KEK:        {info.get('kek', '?')}")
            print(f"  gap:        {info.get('gap', '?')} байт")
            print(f"  prefix:     {info.get('prefix', '?')} байт PDF-шаблона")
            print(f"  template:   {info.get('tpl', '?')}")
            print(f"  файл:       {info.get('file', '?')}")
        else:
            print("  Пока нет строки TRY в логе.")
        print()
        print("Прогресс по CSV/checkpoint:")
        if summary.get("exists"):
            print(f"  строк всего:              {summary.get('rows')}")
            print(f"  завершённых попыток:      {summary.get('done')}")
            print(f"  проверенных моделей sat:  {summary.get('models')}")
            statuses = summary.get("status", Counter())
            if statuses:
                print("  статусы:")
                for key, count in statuses.most_common():
                    print(f"    {key or '(пусто)'}: {count}")
            ok = summary.get("decrypt_ok", [])
            print(f"  успешных decrypt_ok:      {len(ok)}")
            last = summary.get("last") or {}
            if last:
                print("  последняя запись:")
                print(f"    status={last.get('status')} done={last.get('attempt_done')} prefix={last.get('prefix_len')} file={last.get('relative')}")
        else:
            print("  CSV ещё не создан. Это нормально, пока первая Z3-попытка не завершилась.")
        print()
        print("Файлы:")
        print(f"  log: {log if log else 'нет'}")
        print(f"  csv: {csv_path if csv_path else 'ещё нет'}")
        print(f"  err: {err if err else 'нет'}")
        print()
        if err_lines:
            print("Последние строки stderr:")
            for line in err_lines[-8:]:
                print("  " + line)
            print()
        print("Управление:")
        print("  Закрыть это окно можно свободно: расчёт продолжит работать.")
        print(f"  Остановить расчёт: Stop-Process -Id {PID}")
        print()
        print("Обновление каждые 15 секунд.")
        time.sleep(15)


if __name__ == "__main__":
    raise SystemExit(main())
