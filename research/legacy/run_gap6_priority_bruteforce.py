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
import json
import os
import subprocess
import sys
import time
from pathlib import Path


WORK = Path(_project_path('research/legacy'))
EXE = WORK / "gap6_bruteforce_4f_fast.exe"
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
REPORT = REPORTS / "gap6_bruteforce_4f_priority_chunks.csv"
STATE = REPORTS / "gap6_bruteforce_4f_priority_state.json"
TOTAL = 1 << 48


def default_state() -> dict:
    # Guess layout:
    # bits 0..15   = FEK bytes 58..59
    # bits 16..47  = FEK bytes 60..63 as word15
    #
    # These are not cryptographic probabilities. They are weak-implementation
    # probes: low/small PRNG output, high/sentinel-like output, and signed-boundary
    # output. If bytes are truly CSPRNG-uniform, all campaigns are equally likely.
    return {
        "LOW_WORD15": {
            "mode": "up",
            "next": 0x000100000000,  # first 2^32 already benchmarked
            "end": 0x010000000000,   # word15 < 2^24
            "weight": 6,
        },
        "HIGH_WORD15": {
            "mode": "down",
            "next": TOTAL,
            "end": TOTAL - 0x010000000000,  # top 2^40 guesses
            "weight": 3,
        },
        "SIGNED_BOUNDARY": {
            "mode": "up",
            "next": 0x800000000000,
            "end": 0x810000000000,
            "weight": 2,
        },
        "MID_ZERO_HIGH": {
            "mode": "up",
            "next": 0x7f0000000000,
            "end": 0x800000000000,
            "weight": 1,
        },
    }


def load_state() -> dict:
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    state = default_state()
    save_state(state)
    return state


def save_state(state: dict) -> None:
    REPORTS.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2), encoding="utf-8")


def pick_campaign(state: dict, counter: int) -> str | None:
    active: list[tuple[str, int]] = []
    for name, cfg in state.items():
        if cfg["mode"] == "up" and int(cfg["next"]) < int(cfg["end"]):
            active.append((name, int(cfg.get("weight", 1))))
        elif cfg["mode"] == "down" and int(cfg["next"]) > int(cfg["end"]):
            active.append((name, int(cfg.get("weight", 1))))
    if not active:
        return None
    schedule = []
    for name, weight in active:
        schedule.extend([name] * max(1, weight))
    return schedule[counter % len(schedule)]


def parse_found(text: str) -> str | None:
    for line in text.splitlines():
        if line.startswith("FOUND "):
            return line.strip()
    return None


def run_chunk(campaign: str, cfg: dict, chunk: int) -> tuple[str, int, int, float, str, str]:
    mode = cfg["mode"]
    if mode == "up":
        start = int(cfg["next"])
        limit = min(chunk, int(cfg["end"]) - start)
        cfg["next"] = start + limit
    else:
        end = int(cfg["next"])
        limit = min(chunk, end - int(cfg["end"]))
        start = end - limit
        cfg["next"] = start

    env = os.environ.copy()
    env["OMP_NUM_THREADS"] = str(os.cpu_count() or 1)
    t0 = time.time()
    result = subprocess.run(
        [str(EXE), str(limit), str(start)],
        cwd=str(WORK),
        capture_output=True,
        text=True,
        env=env,
    )
    elapsed = time.time() - t0
    status = "FOUND" if parse_found(result.stdout) else "NOT_FOUND"
    return status, start, limit, elapsed, result.stdout, result.stderr


def main() -> int:
    if not EXE.exists():
        print(f"ERROR missing {EXE}", file=sys.stderr)
        return 2
    chunk = int(sys.argv[1], 0) if len(sys.argv) > 1 else (1 << 35)
    max_hours = float(sys.argv[2]) if len(sys.argv) > 2 else 12.0
    max_seconds = max_hours * 3600
    t_start = time.time()
    state = load_state()
    REPORTS.mkdir(parents=True, exist_ok=True)
    exists = REPORT.exists()
    with REPORT.open("a", encoding="utf-8-sig", newline="") as fh:
        fields = ["time", "campaign", "start", "chunk", "status", "elapsed_sec", "stdout", "stderr"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        if not exists:
            writer.writeheader()
        idx = 0
        while time.time() - t_start < max_seconds:
            campaign = pick_campaign(state, idx)
            if campaign is None:
                print("ALL_PRIORITY_CAMPAIGNS_DONE")
                save_state(state)
                return 0
            cfg = state[campaign]
            print(
                f"PRIORITY_CHUNK {idx + 1} campaign={campaign} "
                f"next=0x{int(cfg['next']):012x} chunk={chunk} elapsed_hours={(time.time()-t_start)/3600:.2f}",
                flush=True,
            )
            status, start, limit, elapsed, stdout, stderr = run_chunk(campaign, cfg, chunk)
            writer.writerow(
                {
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "campaign": campaign,
                    "start": f"0x{start:012x}",
                    "chunk": str(limit),
                    "status": status,
                    "elapsed_sec": f"{elapsed:.3f}",
                    "stdout": stdout.replace("\r", "\\r").replace("\n", "\\n"),
                    "stderr": stderr.replace("\r", "\\r").replace("\n", "\\n"),
                }
            )
            fh.flush()
            save_state(state)
            print(stderr, end="", flush=True)
            print(stdout, end="", flush=True)
            print(f"STATE={STATE}", flush=True)
            if status == "FOUND":
                print(f"FOUND campaign={campaign} start=0x{start:012x}")
                return 0
            idx += 1
    print(f"TIME_LIMIT_REACHED hours={max_hours}")
    print(f"REPORT={REPORT}")
    print(f"STATE={STATE}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
