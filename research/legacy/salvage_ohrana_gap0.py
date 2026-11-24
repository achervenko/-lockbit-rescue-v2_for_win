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
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
FOLDER = "ОХРАНА ТРУДА"
EXT = ".xzg9VRelb"
REPORTS = DST_ROOT / "_technical_reports"
SALVAGE_ROOT = REPORTS / "ohrana_gap0_salvage"


def out_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def enc_path_for_rel(rel_path: str) -> Path:
    return SRC_ROOT / FOLDER / (rel_path + EXT)


def build_group_ks(kek: str, files: list[lr.EncryptedFile]) -> dict[int, int]:
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        raise RuntimeError(f"cannot dump ks for {kek}")
    ks = {i: b for i, b in enumerate(base)}
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)

    changed = True
    tried: set[str] = set()
    while changed:
        changed = False
        for item in files:
            if item.path in tried:
                continue
            if not out_path_for(Path(item.path)).exists():
                continue
            fek = rdt.derive_fek_from_ks(ks, item) or rdt.recover_fek_from_known_pair(item, ks)
            if not fek:
                continue
            tried.add(item.path)
            learned = rdt.learn_fek(ks, item, fek)
            if learned:
                changed = True
    return ks


def pdf_soft_check(path: Path) -> tuple[bool, str]:
    data = path.read_bytes()
    if not data.startswith(b"%PDF-"):
        return False, "no_pdf_header"
    eof_pos = data.rfind(b"%%EOF")
    if eof_pos < 0:
        return False, "no_eof"
    try:
        from pypdf import PdfReader

        reader = PdfReader(str(path), strict=False)
        pages = len(reader.pages)
        if pages > 0:
            return True, f"pypdf_pages={pages}"
    except Exception as exc:
        return False, f"pypdf_error={type(exc).__name__}:{exc}"
    return False, "pypdf_zero_pages"


def validate_soft(path: Path, ext: str) -> tuple[bool, str]:
    if ext == "pdf":
        return pdf_soft_check(path)
    if ext in {"htm", "html"}:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore").lower()
        except OSError as exc:
            return False, f"read_error:{exc}"
        if "<html" in text or "<!doctype html" in text:
            return True, "html_marker"
        return False, "no_html_marker"
    if ext == "xml":
        data = path.read_bytes()
        if len(data) == 0:
            return True, "empty_zero_body"
        text = data[:512].decode("utf-8-sig", errors="ignore").lstrip()
        if text.startswith("<?xml") or text.startswith("<"):
            return True, "xml_marker"
        return False, "no_xml_marker"
    return rdt.validate_recovered(path, ext), "strict_validator"


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    SALVAGE_ROOT.mkdir(parents=True, exist_ok=True)

    groups, _, _ = lr.scan_source(
        SRC_ROOT / FOLDER, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1
    )
    item_by_path = {Path(item.path): (kek, files, item) for kek, files in groups.items() for item in files}
    ks_by_kek = {kek: build_group_ks(kek, files) for kek, files in groups.items()}

    analysis = REPORTS / "ohrana_remaining_35_analysis.csv"
    rows = []
    recovered = 0
    attempted = 0
    with analysis.open("r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            if row["recoverability"] != "DIRECT_POSSIBLE" or row["is_temp_office"] != "0":
                continue
            enc = enc_path_for_rel(row["rel_path"])
            out = out_path_for(enc)
            if out.exists() and out.stat().st_size > 0:
                continue
            if enc not in item_by_path:
                row.update({"status": "NO_ITEM", "salvage_path": "", "detail": ""})
                rows.append(row)
                continue

            kek, files, item = item_by_path[enc]
            ks = ks_by_kek[kek]
            fek_hex = rdt.derive_fek_from_ks(ks, item)
            if not fek_hex:
                row.update({"status": "NO_FEK", "salvage_path": "", "detail": ""})
                rows.append(row)
                continue

            before, after, skipped, params_source = rdt.chunking_params_for(item, ks)
            attempted += 1
            salvage_tmp = SALVAGE_ROOT / Path(row["rel_path"]).name
            salvage_tmp.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix="ohrana_gap0_") as td:
                tmp = Path(td) / "dec"
                ok = rdt.direct_decrypt_with_timeout(
                    rdt.REPO / "direct-decrypt.exe",
                    enc,
                    tmp,
                    fek_hex,
                    before,
                    after,
                    hex(skipped),
                )
                if not ok:
                    row.update({"status": "DIRECT_FAILED", "salvage_path": "", "detail": params_source})
                    rows.append(row)
                    continue
                valid, detail = validate_soft(tmp, row["ext"])
                shutil.copy2(tmp, salvage_tmp)
                if valid:
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(tmp, out)
                    recovered += 1
                    status = "RECOVERED_SOFT_VALID"
                else:
                    status = "DECRYPTED_BUT_INVALID"
                row.update({
                    "status": status,
                    "salvage_path": str(salvage_tmp),
                    "detail": f"{detail};{params_source};size={tmp.stat().st_size}",
                })
                rows.append(row)

    report = REPORTS / "ohrana_gap0_salvage_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        fields = list(rows[0].keys()) if rows else ["status"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    print(f"attempted={attempted}")
    print(f"recovered={recovered}")
    print(f"report={report}")
    print(f"salvage_root={SALVAGE_ROOT}")
    for row in rows:
        print(f"{row.get('status')} {row.get('detail')} :: {row.get('rel_path')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
