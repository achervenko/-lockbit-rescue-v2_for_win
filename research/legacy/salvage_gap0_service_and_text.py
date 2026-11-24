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
import shutil
import sys
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЭКСПЛУАТАЦИЯ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from salvage_exploitation_interval_params import decrypt_interval


ENC_ROOT = Path(_case_value('60e26aa6c7e364d54ffa'))
OUT_ROOT = Path(_case_value('89ada5c24a22d61a7d60'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
SALVAGE_ROOT = REPORTS / "gap0_service_text_salvage"
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def plausible_service_lock(data: bytes, rel: Path) -> bool:
    if not rel.name.startswith("~$"):
        return False
    if not 16 <= len(data) <= 1024:
        return False
    # Office owner lock files are short binary records that usually contain
    # an ANSI/Unicode username and lots of NUL/space padding.
    printable = sum(1 for b in data if b in (0, 9, 10, 13, 32) or 0x20 <= b <= 0x7E or 0xC0 <= b <= 0xFF)
    return printable / max(1, len(data)) > 0.80


def plausible_text(data: bytes) -> bool:
    if not data or len(data) > 2 * 1024 * 1024:
        return False
    for enc in ("utf-8-sig", "utf-16le", "cp1251"):
        try:
            text = data.decode(enc)
        except UnicodeDecodeError:
            continue
        if not text.strip():
            continue
        bad = text.count("\ufffd")
        controls = sum(1 for ch in text if ord(ch) < 32 and ch not in "\r\n\t")
        if bad == 0 and controls / max(1, len(text)) < 0.03:
            return True
    return False


def main() -> int:
    SALVAGE_ROOT.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    ks_by_kek: dict[str, dict[int, int]] = {}
    rows = []
    recovered = 0

    for kek, files in sorted(groups.items()):
        for item in sorted(files, key=lambda f: Path(f.path).stat().st_size):
            enc = Path(item.path)
            rel = out_rel_for(enc)
            out = OUT_ROOT / rel
            if out.exists():
                continue
            ext = rel.suffix.lower().lstrip(".")
            if not (rel.name.startswith("~$") or ext in {"txts", "txt", "log"}):
                continue
            if kek not in ks_by_kek:
                ks_by_kek[kek] = build_group_keystream(files)
            ks = ks_by_kek[kek]
            if max(0, item.fei_len - rdt.contiguous(ks)) != 0:
                continue
            fek_hex = rdt.derive_fek_from_ks(ks, item)
            if not fek_hex:
                continue
            before, after, skipped, source = rdt.chunking_params_for(item, ks)
            data = decrypt_interval(enc, fek_hex, before, after, skipped)
            status = ""
            if plausible_service_lock(data, rel):
                status = "RECOVERED_OFFICE_LOCK"
            elif ext in {"txts", "txt", "log"} and plausible_text(data):
                status = "RECOVERED_TEXT"
            else:
                status = "REJECTED"
            rows.append(
                {
                    "status": status,
                    "rel_path": str(rel),
                    "size": len(data),
                    "ext": ext,
                    "params": f"{before}/{after}/0x{skipped:x}/{source}",
                    "head32": data[:32].hex(),
                }
            )
            if status.startswith("RECOVERED"):
                tmp = SALVAGE_ROOT / rel.name
                tmp.write_bytes(data)
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, out)
                recovered += 1
                print(f"{status} {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')}", flush=True)

    report = REPORTS / "gap0_service_text_salvage_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = list(rows[0].keys()) if rows else ["status"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"recovered={recovered}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
