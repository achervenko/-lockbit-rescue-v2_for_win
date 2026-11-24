from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(_project_path(''))
WORK = Path(_project_path('research/legacy'))
ROOT = Path(_case_value('970585ac651f2074f264'))
RUN = Path(_case_value('e06ee002e1fc1aa59873'))
sys.path[:0] = [str(REPO), str(WORK)]

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt

EXT = ".xzg9VRelb"
KEK = _case_value('840bb5a427ea610faa0c')


def scan() -> list[lr.EncryptedFile]:
    out = []
    for p in ROOT.rglob(f"*{EXT}"):
        item = lr.scan_file_worker((str(p.parent), p.name, [EXT], set(), True))
        if item and item.kek_fingerprint == KEK:
            out.append(item)
    return out


def initial_ks(files: list[lr.EncryptedFile]) -> dict[int, int]:
    ks: dict[int, int] = {}
    for item in sorted(files, key=lambda x: x.coverage, reverse=True):
        dumped = rdt.run_dump_ks(item)
        if dumped:
            for i, b in enumerate(dumped):
                if i in ks and ks[i] != b:
                    raise RuntimeError(f"keystream conflict at {i}")
                ks[i] = b
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def parse(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def run_one(item: lr.EncryptedFile, oracle: lr.EncryptedFile,
            ks: dict[int, int], label: str) -> dict[str, str]:
    cov = rdt.contiguous(ks)
    gap = item.fei_len - cov
    before, after, skipped, source = rdt.chunking_params_for(item, ks)
    RUN.mkdir(parents=True, exist_ok=True)
    target_copy = RUN / f"{label}_target.bin"
    oracle_copy = RUN / "oracle.bin"
    shutil.copy2(item.path, target_copy)
    shutil.copy2(oracle.path, oracle_copy)
    ext_hex = rdt.ks_ext_hex(ks, oracle.coverage, cov)
    base = [
        str(REPO / "brute-extend.exe"), str(target_copy), str(oracle_copy),
        "hex:" + oracle.original_name.encode("utf-8").hex(),
        "", str(gap), str(before), str(after), hex(skipped), ext_hex,
    ]
    print(json.dumps({"stage": label, "coverage": cov, "fei_len": item.fei_len,
                      "gap": gap, "params": [before, after, hex(skipped), source]},
                     ensure_ascii=False), flush=True)
    for magic in ("ffd8ffe1", "ffd8ffe0", "ffd8ff"):
        cmd = base[:]
        cmd[4] = magic
        print(f"TRY {label} magic={magic}", flush=True)
        proc = subprocess.run(cmd, text=True, capture_output=True)
        if proc.stderr:
            print(proc.stderr, file=sys.stderr, flush=True)
        if proc.stdout:
            print(proc.stdout, flush=True)
        result = parse(proc.stdout)
        if result.get("STATUS") in {"OK_BRUTE", "OK_NOBRUTE"} and result.get("FEK"):
            learned = rdt.learn_fek(ks, item, result["FEK"])
            print(f"FOUND {label} magic={magic} learned={learned} coverage={rdt.contiguous(ks)}", flush=True)
            return result
    raise RuntimeError(f"no valid JPEG candidate for {label}")


def main() -> None:
    files = scan()
    ks = initial_ks(files)
    oracle = max(files, key=lambda x: x.coverage)
    by_name = {x.original_name: x for x in files}
    if rdt.contiguous(ks) < 106:
        cached_fek = _case_value('445184bd2f1976e07301')
        learned = rdt.learn_fek(ks, by_name[_case_value('a1b96a939ae03a070fae')], cached_fek)
        result4 = {"STATUS": "OK_BRUTE_CACHED", "KSEXT": "5a341716", "FEK": cached_fek}
        print(f"RESTORED gap4 learned={learned} coverage={rdt.contiguous(ks)}", flush=True)
    else:
        result4 = {"STATUS": "ALREADY_KNOWN"}
    result2 = run_one(by_name[_case_value('7d817478e11a22b46218')], oracle, ks, "gap2")
    target = by_name[_case_value('a2be1c0676f3efd542bf')]
    state = {
        "kek": KEK,
        "coverage": rdt.contiguous(ks),
        "keystream_hex": bytes(ks[i] for i in range(rdt.contiguous(ks))).hex(),
        "target_fei_len": target.fei_len,
        "target_remaining": target.fei_len - rdt.contiguous(ks),
        "gap4": result4,
        "gap2": result2,
    }
    state_path = RUN / "state.json"
    state_path.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(state, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
