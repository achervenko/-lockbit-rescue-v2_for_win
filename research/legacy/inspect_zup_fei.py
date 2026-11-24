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
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


P = Path(_case_value('3ad29af15411aaf877ae'))


def main() -> int:
    fei_len, off, body_end, fei, kek = lr.read_fei_ciphertext(P)
    print("fei_len", fei_len)
    print("fei_offset", off)
    print("body_end", body_end)
    print("kek", lr.kek_fingerprint(kek))
    print("fei_head", fei[:256].hex())
    print("fei_mid_64", fei[9600:9664].hex())
    print("fei_tail", fei[-256:].hex())
    with P.open("rb") as f:
        print("body_head_enc", f.read(256).hex())
        f.seek(0x20000)
        print("body_20000_enc", f.read(64).hex())
        f.seek(0x520000)
        print("body_520000_enc", f.read(64).hex())
        f.seek(body_end - 256)
        print("body_tail_enc", f.read(256).hex())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
