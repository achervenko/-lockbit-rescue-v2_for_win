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
import sys
import zipfile
from pathlib import Path, PurePosixPath

REPO = Path(_project_path(''))
sys.path.insert(0, str(REPO))
import lockbit_rescue_v2 as lr

ARCHIVE = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(_case_value('b9ed1cf0c5e45825c541'))
OUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(_case_value('970585ac651f2074f264'))
EXT = ".xzg9VRelb"


def decoded_name(info: zipfile.ZipInfo) -> str:
    name = info.filename
    if not (info.flag_bits & 0x800):
        try:
            name = name.encode("cp437").decode("cp866")
        except (UnicodeEncodeError, UnicodeDecodeError):
            pass
    return name


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with zipfile.ZipFile(ARCHIVE) as zf:
        for info in zf.infolist():
            name = decoded_name(info)
            if info.is_dir() or not name.endswith(EXT):
                continue
            parts = [p for p in PurePosixPath(name).parts if p not in ("", ".", "..")]
            dest = OUT.joinpath(*parts)
            dest.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, dest.open("wb") as dst:
                shutil.copyfileobj(src, dst, 1024 * 1024)
            extracted.append(dest)

    rows = []
    for p in extracted:
        item = lr.scan_file_worker((str(p.parent), p.name, [EXT], set(), True))
        if item:
            rows.append({
                "path": str(p), "name": p.name, "size": item.size,
                "fei_len": item.fei_len, "coverage": item.coverage,
                "kek": item.kek_fingerprint,
            })
    target_kek = _case_value('840bb5a427ea610faa0c')
    matches = sorted((r for r in rows if r["kek"] == target_kek),
                     key=lambda r: r["coverage"], reverse=True)
    print(json.dumps({
        "extracted": len(extracted),
        "groups": len({r["kek"] for r in rows}),
        "target_matches": len(matches),
        "matches": matches,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
