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
RUN = Path(_case_value('e06ee002e1fc1aa59873'))
ROOTS = [
    Path(_case_value('970585ac651f2074f264')),
    Path(_case_value('6c2cd6c9e052347de1b2')),
]
sys.path[:0] = [str(REPO), str(WORK)]
import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


def parse(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def main() -> None:
    files = []
    for root in ROOTS:
        for p in root.rglob("*.xzg9VRelb"):
            x = lr.scan_file_worker((str(p.parent), p.name, [".xzg9VRelb"], set(), True))
            if x and x.kek_fingerprint == _case_value('840bb5a427ea610faa0c'):
                files.append(x)
    ks = {}
    for x in sorted(files, key=lambda z: z.coverage, reverse=True):
        b = rdt.run_dump_ks(x)
        if b:
            for i, v in enumerate(b):
                if i in ks and ks[i] != v:
                    raise RuntimeError(f"conflict {i}")
                ks[i] = v
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    by_name = {x.original_name: x for x in files}

    img = by_name[_case_value('7d817478e11a22b46218')]
    img_fek = _case_value('0764cfc9e8c4fc00e342')
    rdt.learn_fek(ks, img, img_fek)
    if rdt.contiguous(ks) != 108:
        raise RuntimeError(f"expected coverage 108, got {rdt.contiguous(ks)}")

    target = by_name[_case_value('4a9d5ab896bd99ac4ea4')]
    oracle = max(files, key=lambda x: x.coverage)
    before, after, skipped, source = rdt.chunking_params_for(target, ks)
    RUN.mkdir(parents=True, exist_ok=True)
    target_copy, oracle_copy = RUN / "gap3_pdf_target.bin", RUN / "oracle_88.bin"
    shutil.copy2(target.path, target_copy)
    shutil.copy2(oracle.path, oracle_copy)
    cmd = [
        str(REPO / "brute-extend.exe"), str(target_copy), str(oracle_copy),
        "hex:" + oracle.original_name.encode("utf-8").hex(),
        "255044462d312e", "3", str(before), str(after), hex(skipped),
        rdt.ks_ext_hex(ks, oracle.coverage, rdt.contiguous(ks)),
    ]
    print(json.dumps({"stage": "gap3_pdf", "coverage": 108, "target": target.original_name,
                      "params": [before, after, hex(skipped), source]}, ensure_ascii=False), flush=True)
    proc = subprocess.run(cmd, text=True, capture_output=True)
    print(proc.stderr, file=sys.stderr, flush=True)
    print(proc.stdout, flush=True)
    result = parse(proc.stdout)
    if result.get("STATUS") != "OK_BRUTE" or not result.get("FEK"):
        raise RuntimeError("gap3 PDF brute force failed")
    rdt.learn_fek(ks, target, result["FEK"])
    state = {
        "kek": _case_value('840bb5a427ea610faa0c'),
        "coverage": rdt.contiguous(ks),
        "keystream_hex": bytes(ks[i] for i in range(rdt.contiguous(ks))).hex(),
        "gap2_image": {"ks_ext": "4bd3", "fek": img_fek},
        "gap3_pdf": result,
        "next": min((x for x in files if x.fei_len > rdt.contiguous(ks)), key=lambda x: x.fei_len).original_name,
        "next_fei_len": min(x.fei_len for x in files if x.fei_len > rdt.contiguous(ks)),
    }
    (RUN / "state.json").write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(state, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
