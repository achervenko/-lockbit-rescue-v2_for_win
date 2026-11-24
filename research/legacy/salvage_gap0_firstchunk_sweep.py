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
from salvage_exploitation_tail_modes import decrypt_variant
from salvage_gap0_relaxed_typed import office_zip_status, pdf_status


ENC_ROOT = Path(_case_value('60e26aa6c7e364d54ffa'))
OUT_ROOT = Path(_case_value('89ada5c24a22d61a7d60'))
REPORTS = Path(_case_value('4fc7deea4d89b4fa8e6a'))
SALVAGE_ROOT = REPORTS / "gap0_firstchunk_sweep_salvage"
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def typed_ok(data: bytes, ext: str) -> tuple[bool, str]:
    if ext == "pdf":
        if not data.startswith((b"%PDF-", b"\xef\xbb\xbf%PDF-")):
            return False, "not_pdf"
        tail = data[-65536:]
        if b"%%EOF" not in tail or b"startxref" not in tail:
            return False, "no_pdf_tail"
        return pdf_status(data)
    if ext in {"docx", "xlsx", "pptx"}:
        return office_zip_status(data, ext)
    if ext in {"doc", "msg", "sldprt"}:
        ok = data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1")
        return ok, "ole_header" if ok else "not_ole"
    if ext == "tmp":
        if data.startswith(b"%PDF-"):
            return pdf_status(data)
        if data.startswith(b"PK\x03\x04"):
            return office_zip_status(data, "docx")
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return True, "ole_header"
        return False, "tmp_unknown"
    return False, "unsupported"


def main() -> int:
    SALVAGE_ROOT.mkdir(parents=True, exist_ok=True)
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    ks_by_kek: dict[str, dict[int, int]] = {}
    rows = []
    recovered = 0

    candidates = []
    for kek, files in groups.items():
        for item in files:
            enc = Path(item.path)
            rel = out_rel_for(enc)
            out = OUT_ROOT / rel
            if out.exists():
                continue
            ext = rel.suffix.lower().lstrip(".")
            size = enc.stat().st_size
            if ext not in {"pdf", "docx", "xlsx", "pptx", "sldprt", "tmp"}:
                continue
            if size > 1024 * 1024:
                continue
            candidates.append((size, rel, kek, files, item, ext, enc, out))

    for _, rel, kek, files, item, ext, enc, out in sorted(candidates, key=lambda row: (row[0], row[1].as_posix().lower())):
        if kek not in ks_by_kek:
            ks_by_kek[kek] = build_group_keystream(files)
        ks = ks_by_kek[kek]
        if max(0, item.fei_len - rdt.contiguous(ks)) != 0:
            continue
        fek_hex = rdt.derive_fek_from_ks(ks, item)
        if not fek_hex:
            continue
        print(f"TRY {ext} {enc.stat().st_size} {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')}", flush=True)
        best = "no_variant"
        for mode in ("continuous", "reset", "offset", "chunk_index"):
            for first in range(0, 5):
                for tail in range(0, 4):
                    data = decrypt_variant(enc, fek_hex, first, tail, mode)
                    ok, detail = typed_ok(data, ext)
                    if not ok:
                        if best == "no_variant":
                            best = f"{detail};mode={mode};first={first};tail={tail};head={data[:8].hex()}"
                        continue
                    tmp = SALVAGE_ROOT / f"{rel.name}.{mode}.{first}_{tail}"
                    tmp.write_bytes(data)
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(tmp, out)
                    recovered += 1
                    best = f"RECOVERED {detail};mode={mode};first={first};tail={tail}"
                    print(f"RECOVERED {str(rel).encode('unicode_escape', errors='backslashreplace').decode('ascii')} {best}", flush=True)
                    break
                if best.startswith("RECOVERED"):
                    break
            if best.startswith("RECOVERED"):
                break
        rows.append({"rel_path": str(rel), "ext": ext, "size": enc.stat().st_size, "result": best})

    report = REPORTS / "gap0_firstchunk_sweep_report.csv"
    with report.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rel_path", "ext", "size", "result"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"recovered={recovered}")
    print(f"report={report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
