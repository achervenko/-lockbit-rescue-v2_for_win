from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


from pathlib import Path
import os
import subprocess
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


REPO = Path(_project_path(''))
P = Path(_case_value('3ad29af15411aaf877ae'))
NAME = "ZUP_backup_2026_08_16_000002_1403489"
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000


def parse(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def main() -> int:
    env = os.environ.copy()
    env["PATH"] = _case_value('88684c479cc30142395a') + env.get("PATH", "")
    name_arg = "hex:" + NAME.encode("utf-8").hex()
    dump = subprocess.run(
        [str(REPO / "brute-extend.exe"), "--dump-ks", str(P), name_arg],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )
    print(dump.stdout)
    parsed = parse(dump.stdout)
    fei_len, _, _, fei, _ = lr.read_fei_ciphertext(P)
    name_len = int(parsed["NAME_KS_LEN"])
    filename_size = int(parsed["FILENAME_SIZE"])
    metadata = (
        filename_size.to_bytes(2, "little")
        + SKIPPED.to_bytes(8, "little")
        + BEFORE.to_bytes(4, "little")
        + AFTER.to_bytes(4, "little")
    )
    ks_ext = bytes(fei[name_len + i] ^ b for i, b in enumerate(metadata)).hex()
    print("metadata_ks_ext_len", len(ks_ext) // 2)
    for label, magic in [
        ("zip", "504b0304"),
        ("gzip", "1f8b08"),
        ("rar", _case_value('3a0b3bec9ccafa7a208c')),
        ("ole", "d0cf11e0a1b11ae1"),
        ("1cd_ascii", "314344"),
        ("sqlite", _case_value('99d60194134d1642e5ee')),
    ]:
        print("TRY", label, magic)
        res = subprocess.run(
            [
                str(REPO / "brute-extend.exe"),
                str(P),
                str(P),
                name_arg,
                magic,
                "4",
                str(BEFORE),
                str(AFTER),
                hex(SKIPPED),
                ks_ext,
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
        )
        print("STDOUT")
        print(res.stdout)
        print("STDERR")
        print(res.stderr)
    print("fei_len", fei_len, "name_len", name_len, "known_with_metadata", name_len + len(metadata))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
