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
import struct

P = Path(_case_value('f4560f9e5b634626d7ec'))


def main() -> int:
    for off in [0x4AA80805, 0x50F49953]:
        with P.open("rb") as f:
            f.seek(off - 64)
            data = f.read(256)
        i = 64
        print(f"OFF {off:#x}")
        print(f"context={data.hex()}")
        print(f"sig={data[i:i+4]!r}")
        if data[i:i+4] == b"PK\x05\x06":
            print("eocd_fields", struct.unpack_from("<4s4H2LH", data, i))
        if data[i:i+4] == b"PK\x01\x02":
            print("cdir_fields", struct.unpack_from("<4s6H3L5H2L", data, i))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
