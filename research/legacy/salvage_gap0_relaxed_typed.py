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
import sys
import zipfile
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЭКСПЛУАТАЦИЯ"
os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from salvage_exploitation_interval_params import decrypt_interval

try:
    from pypdf import PdfReader
except Exception:  # pragma: no cover
    PdfReader = None


ENC_ROOT = Path(_case_value('60e26aa6c7e364d54ffa'))
OUT_ROOT = Path(_case_value('89ada5c24a22d61a7d60'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
SALVAGE_ROOT = REPORTS / "gap0_relaxed_typed_salvage"
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def office_zip_status(data: bytes, ext: str) -> tuple[bool, str]:
    if not data.startswith(b"PK\x03\x04"):
        return False, "not_zip"
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = set(zf.namelist())
            bad = zf.testzip()
    except Exception as exc:
        return False, "zip_error:" + type(exc).__name__
    expected = {
        "docx": "word/",
        "xlsx": "xl/",
        "pptx": "ppt/",
    }.get(ext)
    if "[Content_Types].xml" not in names or (expected and not any(n.startswith(expected) for n in names)):
        return False, f"zip_names_no_{expected or 'office'}"
    if bad:
        return False, "zip_crc_bad:" + bad
    return True, f"zip_ok entries={len(names)}"


def pdf_status(data: bytes) -> tuple[bool, str]:
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
            if max(0, item.fei_len - rdt.contiguous(ks)) != 0:
                continue
            fek_hex = rdt.derive_fek_from_ks(ks, item)
            if not fek_hex:
                continue
            before, after, skipped, source = rdt.chunking_params_for(item, ks)
            data = decrypt_interval(enc, fek_hex, before, after, skipped)
            status = "REJECTED"
            detail = ""

            if rel.name.startswith("~$") and len(data) <= 1024:
                status = "RECOVERED_OFFICE_LOCK_FORCE"
                detail = "short_lock_file"
            elif ext == "accdb" and data.startswith(bytes.fromhex(_case_value('fc333b7534d960ad91f4'))):
                status = "RECOVERED_ACCDB_HEADER_VALID"
                detail = "access_header"
            elif ext == "pptx" and data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
                status = "RECOVERED_OLE_MISNAMED_PPTX"
                detail = "ole_compound_file_header"
            elif ext in {"docx", "xlsx", "pptx"}:
                ok, detail = office_zip_status(data, ext)
                if ok:
                    status = "RECOVERED_OFFICE_ZIP"
            elif ext == "pdf":
                ok, detail = pdf_status(data)
                if ok:
                    status = "RECOVERED_PDF_RELAXED"

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
            if status.startswith("RECOVERED"):
                tmp = SALVAGE_ROOT / rel.name
                tmp.write_bytes(data)
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, out)
                recovered += 1
                print(f"{status} {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')} {detail}", flush=True)

    report = REPORTS / "gap0_relaxed_typed_salvage_report.csv"
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
