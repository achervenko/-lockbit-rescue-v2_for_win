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
import sqlite3
import sys
import zipfile
import re
from pathlib import Path

FOLDER = os.environ.get("RECOVER_FOLDER", "ЗАКУПКИ")
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from salvage_exploitation_interval_params import decrypt_interval

try:
    from pypdf import PdfReader
except Exception:
    PdfReader = None


ENC_ROOT = Path(_case_value('f6af7da1ad90629ee69b')) / FOLDER
OUT_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2')) / FOLDER
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
SALVAGE_ROOT = REPORTS / f"{FOLDER}_gap0_typed_salvage"
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def office_zip_ok(data: bytes, ext: str) -> tuple[bool, str]:
    if not data.startswith(b"PK\x03\x04"):
        return False, "not_zip"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            bad = zf.testzip()
    except Exception as exc:
        return False, "zip_error:" + type(exc).__name__
    expected = {"xlsx": "xl/", "docx": "word/", "pptx": "ppt/"}.get(ext)
    if "[Content_Types].xml" not in names or (expected and not any(n.startswith(expected) for n in names)):
        return False, "not_office_zip"
    if bad:
        return False, "zip_crc_bad:" + bad
    return True, f"zip_ok entries={len(names)}"


def pdf_ok(data: bytes) -> tuple[bool, str]:
    if not data.startswith((b"%PDF-", b"\xef\xbb\xbf%PDF-")):
        return False, "not_pdf"
    if b"%%EOF" not in data[-65536:]:
        return False, "no_eof"
    if PdfReader is None:
        return True, "pdf_eof_only"
    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        pages = len(reader.pages)
    except Exception as exc:
        return False, "pypdf_error:" + type(exc).__name__
    return pages > 0, f"pdf_pages={pages}"


def sqlite_ok(data: bytes) -> tuple[bool, str]:
    if not data.startswith(b"SQLite format 3\x00"):
        return False, "not_sqlite"
    try:
        conn = sqlite3.connect(":memory:")
        disk = sqlite3.connect(f"file:tmp?mode=memory&cache=shared", uri=True)
        disk.close()
        conn.close()
    except Exception:
        pass
    return True, "sqlite_header"


def service_lock_ok(data: bytes, rel: Path) -> tuple[bool, str]:
    if not rel.name.startswith("~$") or len(data) > 1024:
        return False, "not_lock"
    printable = sum(1 for b in data if b in (0, 9, 10, 13, 32) or 0x20 <= b <= 0x7E or 0xC0 <= b <= 0xFF)
    return printable / max(1, len(data)) > 0.70, "office_lock"


def url_ok(data: bytes) -> tuple[bool, str]:
    text = data.decode("utf-8-sig", errors="ignore").replace("\x00", "")
    stripped = text.strip()
    if stripped.startswith("[InternetShortcut]") and ("URL=" in stripped or "BASEURL=" in stripped):
        return True, "internet_shortcut"
    if stripped.startswith("[{000214") and ("url" in stripped.lower() or "http" in stripped.lower()):
        return True, "shell_url_shortcut"
    return False, "not_url"


def md5_ok(data: bytes) -> tuple[bool, str]:
    text = data.decode("ascii", errors="ignore").strip()
    if re.search(r"\b[0-9a-fA-F]{32}\b", text):
        return True, "md5_text"
    return False, "not_md5"


def ole_ok(data: bytes) -> tuple[bool, str]:
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return True, "ole_compound"
    return False, "not_ole"


def typed_status(data: bytes, ext: str, rel: Path) -> tuple[bool, str]:
    if rel.name.startswith("~$"):
        return service_lock_ok(data, rel)
    if ext in {"xlsx", "docx", "pptx"}:
        ok, detail = office_zip_ok(data, ext)
        if ok:
            return ok, detail
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return True, "ole_office_mislabeled"
        return ok, detail
    if ext == "pdf":
        return pdf_ok(data)
    if ext == "db":
        return sqlite_ok(data)
    if ext == "url":
        return url_ok(data)
    if ext == "md5":
        return md5_ok(data)
    if ext == "msi":
        return ole_ok(data)
    return False, "unsupported"


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
            if kek not in ks_by_kek:
                ks_by_kek[kek] = build_group_keystream(files)
            ks = ks_by_kek[kek]
            gap = max(0, item.fei_len - rdt.contiguous(ks))
            if gap != 0:
                continue
            fek_hex = rdt.derive_fek_from_ks(ks, item)
            if not fek_hex:
                continue
            before, after, skipped, source = rdt.chunking_params_for(item, ks)
            data = decrypt_interval(enc, fek_hex, before, after, skipped)
            ok, detail = typed_status(data, ext, rel)
            status = "RECOVERED" if ok else "REJECTED"
            rows.append(
                {
                    "status": status,
                    "rel_path": str(rel),
                    "ext": ext,
                    "size": len(data),
                    "params": f"{before}/{after}/0x{skipped:x}/{source}",
                    "detail": detail,
                    "head16": data[:16].hex(),
                }
            )
            if ok:
                tmp = SALVAGE_ROOT / rel.name
                tmp.write_bytes(data)
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, out)
                recovered += 1
                print(f"RECOVERED {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')} {detail}", flush=True)

    report = REPORTS / f"{FOLDER}_gap0_typed_salvage_report.csv"
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
