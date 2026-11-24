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
import io
import os
import shutil
import struct
import sys
import zipfile
import zlib
from pathlib import Path

FOLDER = os.environ.get("RECOVER_FOLDER", "ЗАКУПКИ")
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from salvage_exploitation_interval_params import decrypt_interval


ENC_ROOT = Path(_case_value('f6af7da1ad90629ee69b')) / FOLDER
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2')) / FOLDER
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
SALVAGE_ROOT = REPORTS / f"{FOLDER}_gap0_zip_spotlight_salvage"
EXT = ".xzg9VRelb"
SPOTLIGHT_EXTS = {
    "shadow",
    "directorystorefile",
    "indexarrays",
    "indexbigdates",
    "indexcompactdirectory",
    "indexdirectory",
    "indexgroups",
    "indexhead",
    "indexids",
    "indexpositions",
    "indexpositiontable",
    "indexpostings",
    "indextermids",
    "shadowindexarrays",
    "shadowindexcompactdirectory",
    "shadowindexdirectory",
    "shadowindexgroups",
    "shadowindexhead",
    "shadowindextermids",
    "updates",
    "state",
    "plist",
}


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def rebuild_zip_from_local_headers(data: bytes) -> tuple[bytes | None, str]:
    out = io.BytesIO()
    count = 0
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        pos = 0
        while True:
            sig = data.find(b"PK\x03\x04", pos)
            if sig < 0:
                break
            if sig + 30 > len(data):
                break
            fields = struct.unpack_from("<IHHHHHIIIHH", data, sig)
            _, ver, flag, method, mtime, mdate, crc, comp_size, uncomp_size, name_len, extra_len = fields
            name_start = sig + 30
            name_end = name_start + name_len
            extra_end = name_end + extra_len
            if extra_end > len(data):
                break
            try:
                name = data[name_start:name_end].decode("utf-8" if flag & 0x800 else "cp437")
            except UnicodeDecodeError:
                name = data[name_start:name_end].decode("utf-8", errors="replace")
            if not name or name.endswith("/"):
                pos = extra_end
                continue
            if flag & 0x08:
                next_sig = data.find(b"PK\x03\x04", extra_end)
                if next_sig < 0:
                    next_sig = data.find(b"PK\x01\x02", extra_end)
                if next_sig < 0:
                    break
                comp_blob = data[extra_end:next_sig]
                pos = next_sig
            else:
                comp_blob = data[extra_end:extra_end + comp_size]
                pos = extra_end + comp_size
            try:
                if method == 0:
                    plain = comp_blob
                elif method == 8:
                    plain = zlib.decompress(comp_blob, -15)
                else:
                    continue
            except zlib.error:
                continue
            info = zipfile.ZipInfo(name)
            info.date_time = (1980 + ((mdate >> 9) & 0x7F), (mdate >> 5) & 0x0F or 1, mdate & 0x1F or 1, (mtime >> 11) & 0x1F, (mtime >> 5) & 0x3F, (mtime & 0x1F) * 2)
            zout.writestr(info, plain)
            count += 1
    rebuilt = out.getvalue()
    if count == 0:
        return None, "no_entries"
    try:
        with zipfile.ZipFile(io.BytesIO(rebuilt)) as zf:
            names = set(zf.namelist())
            bad = zf.testzip()
    except Exception as exc:
        return None, "rebuilt_bad:" + type(exc).__name__
    if bad:
        return None, "crc_bad:" + bad
    return rebuilt, f"entries={count} names={len(names)}"


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
            if ext not in {"xlsx", "docx", "pptx", "db"} | SPOTLIGHT_EXTS:
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
            status = "REJECTED"
            detail = ""
            payload = data
            if ext == "db" and data.startswith(b"8tsd"):
                status = "RECOVERED_SPOTLIGHT_DB"
                detail = "8tsd_header"
            elif ext in SPOTLIGHT_EXTS:
                status = "RECOVERED_SPOTLIGHT_TECH"
                detail = f"technical_{ext}"
            elif ext in {"xlsx", "docx", "pptx"} and data.startswith(b"PK\x03\x04"):
                rebuilt, detail = rebuild_zip_from_local_headers(data)
                if rebuilt:
                    payload = rebuilt
                    status = "RECOVERED_REBUILT_ZIP"
            rows.append({"status": status, "rel_path": str(rel), "ext": ext, "detail": detail, "head16": data[:16].hex()})
            if status.startswith("RECOVERED"):
                tmp = SALVAGE_ROOT / rel.name
                tmp.write_bytes(payload)
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, out)
                recovered += 1
                print(f"{status} {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')} {detail}", flush=True)

    report = REPORTS / f"{FOLDER}_gap0_zip_spotlight_salvage_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = list(rows[0].keys()) if rows else ["status"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"folder={FOLDER}")
    print(f"recovered={recovered}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
