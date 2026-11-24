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
import re
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
EXT = ".xzg9VRelb"


def safe_name(path: Path) -> str:
    text = str(path.relative_to(SRC_ROOT))
    text = re.sub(r"[^\w.\-]+", "_", text, flags=re.UNICODE)
    return text[-180:]


def build_group_ks(files: list[lr.EncryptedFile]) -> dict[int, int] | None:
    oracle = max(files, key=lambda f: f.coverage)
    base = rdt.run_dump_ks(oracle)
    if not base:
        return None
    ks = {i: b for i, b in enumerate(base)}
    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        more = rdt.run_dump_ks(item)
        if not more:
            continue
        for off, val in enumerate(more):
            rdt.merge_ks(ks, off, val)
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    return ks


def summarize(path: Path, ext: str) -> dict[str, str]:
    data = path.read_bytes()
    tail = data[-65536:] if len(data) > 65536 else data
    out = {
        "size": str(len(data)),
        "head_hex": data[:32].hex(),
        "starts_pdf": str(data.startswith(b"%PDF-")),
        "eof_last_4k": str(b"%%EOF" in data[-4096:]),
        "eof_last_64k": str(b"%%EOF" in tail),
        "eof_any": str(b"%%EOF" in data),
        "validate": str(rdt.validate_recovered(path, ext)),
    }
    if ext in {"docx", "xlsx", "pptx", "xlsm", "xlsb", "vsdx"}:
        import zipfile

        try:
            with zipfile.ZipFile(path) as zf:
                names = zf.namelist()
            out["zip_ok"] = "True"
            out["zip_names"] = ";".join(names[:12])
        except Exception as exc:
            out["zip_ok"] = "False"
            out["zip_error"] = type(exc).__name__
    return out


def main() -> int:
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 30
    probe_dir = REPORTS / "probe_gap0"
    probe_dir.mkdir(parents=True, exist_ok=True)

    groups: dict[str, list[lr.EncryptedFile]] = defaultdict(list)
    for root in [p for p in SRC_ROOT.iterdir() if p.is_dir()]:
        scanned_groups, _, _ = lr.scan_source(root, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
        for kek, files in scanned_groups.items():
            groups[kek].extend(files)

    candidate_csv = REPORTS / "next_recovery_candidate_files.csv"
    rows = list(csv.DictReader(candidate_csv.open(encoding="utf-8-sig")))
    wanted = [r for r in rows if r["gap"] == "0" and r["ext"] in {"pdf", "docx", "xlsx", "pptx", "doc", "dav", "sldprt", "sldasm", "dxf"}]
    wanted = wanted[:limit]

    report_rows = []
    ks_by_kek: dict[str, dict[int, int]] = {}
    by_path = {str(Path(item.path)): item for files in groups.values() for item in files}
    for row in wanted:
        path = Path(row["path"])
        item = by_path.get(str(path))
        if item is None:
            continue
        kek = row["kek"]
        if kek not in ks_by_kek:
            ks = build_group_ks(groups[kek])
            if ks is None:
                continue
            ks_by_kek[kek] = ks
        ks = ks_by_kek[kek]
        fek_hex = rdt.derive_fek_from_ks(ks, item)
        if not fek_hex:
            continue
        before, after, skipped, params_source = rdt.chunking_params_for(item, ks)
        out = probe_dir / safe_name(path.with_suffix(""))
        ok = rdt.direct_decrypt_with_timeout(
            rdt.REPO / "direct-decrypt.exe",
            path,
            out,
            fek_hex,
            before,
            after,
            hex(skipped),
        )
        summary = {"kek": kek, "ext": row["ext"], "path": str(path), "probe_path": str(out), "direct_ok": str(ok), "params": f"{hex(skipped)}/{before}/{after}/{params_source}"}
        if ok:
            summary.update(summarize(out, row["ext"]))
        report_rows.append(summary)
        print(summary)

    report = REPORTS / "probe_gap0_report.csv"
    fields = sorted({k for row in report_rows for k in row})
    with report.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(report_rows)
    print(f"wrote={report}")
    print(f"probe_dir={probe_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
