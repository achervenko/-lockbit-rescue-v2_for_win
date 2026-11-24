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
import os
import subprocess
import sys
import time
from pathlib import Path


WORK = Path(_project_path('research/legacy'))
EXE = WORK / "gap6_bruteforce_4f_fast.exe"
REPORT = Path(_case_value('45a6fad3dedb90d6035e'))
STATE = Path(_case_value('57a107125e037a2e3acb'))


def parse_found(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("FOUND "):
            return line.strip()
    return None


def main() -> int:
    if not EXE.exists():
        print(f"ERROR missing {EXE}", file=sys.stderr)
        return 2
    chunk = int(sys.argv[1], 0) if len(sys.argv) > 1 else (1 << 34)
    chunks = int(sys.argv[2], 0) if len(sys.argv) > 2 else 1
    start = int(sys.argv[3], 0) if len(sys.argv) > 3 else (int(STATE.read_text().strip(), 0) if STATE.exists() else 0)
    total = 1 << 48
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    exists = REPORT.exists()
    with REPORT.open("a", encoding="utf-8-sig", newline="") as fh:
        fields = ["start", "chunk", "status", "elapsed_sec", "stdout", "stderr"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        for idx in range(chunks):
            if start >= total:
                print("DONE_FULL_RANGE")
                return 0
            limit = min(chunk, total - start)
            print(f"CHUNK {idx+1}/{chunks} start=0x{start:012x} limit={limit} ({limit/2**30:.2f}G guesses)", flush=True)
            t0 = time.time()
            env = os.environ.copy()
            env["OMP_NUM_THREADS"] = str(os.cpu_count() or 1)
            result = subprocess.run(
                [str(EXE), str(limit), str(start)],
                cwd=str(WORK),
                capture_output=True,
                text=True,
                env=env,
            )
            elapsed = time.time() - t0
            found = parse_found(result.stdout)
            status = "FOUND" if found else "NOT_FOUND"
            writer.writerow(
                {
                    "start": f"0x{start:012x}",
                    "chunk": str(limit),
                    "status": status,
                    "elapsed_sec": f"{elapsed:.3f}",
                    "stdout": result.stdout.replace("\r", "\\r").replace("\n", "\\n"),
                    "stderr": result.stderr.replace("\r", "\\r").replace("\n", "\\n"),
                }
            )
            fh.flush()
            print(result.stderr, end="", flush=True)
            print(result.stdout, end="", flush=True)
            if found:
                STATE.write_text(f"0x{start:012x}\n", encoding="ascii")
                print(f"FOUND_AT_CHUNK_START=0x{start:012x}")
                return 0
            start += limit
            STATE.write_text(f"0x{start:012x}\n", encoding="ascii")
            print(f"NEXT_START=0x{start:012x}", flush=True)
    print(f"REPORT={REPORT}")
    print(f"STATE={STATE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
