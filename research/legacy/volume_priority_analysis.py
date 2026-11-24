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
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
RANSOM_EXT = ".xzg9VRelb"


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(RANSOM_EXT)])


def original_ext(enc: Path) -> str:
    name = enc.name[: -len(RANSOM_EXT)] if enc.name.endswith(RANSOM_EXT) else enc.name
    return name.rsplit(".", 1)[-1].lower() if "." in name else "<noext>"


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups: dict[str, dict] = defaultdict(lambda: {
        "total_count": 0,
        "recovered_count": 0,
        "remaining_count": 0,
        "total_bytes": 0,
        "recovered_enc_bytes": 0,
        "remaining_bytes": 0,
        "min_fei": 10**9,
        "max_fei": 0,
        "max_recovered_fei": 0,
        "folders": Counter(),
        "remaining_exts": Counter(),
        "remaining_ext_bytes": Counter(),
        "biggest": [],
    })

    for enc in SRC_ROOT.rglob(f"*{RANSOM_EXT}"):
        try:
            fei_len, _, _, _, kek = lr.read_fei_ciphertext(enc)
        except Exception:
            continue
        fp = lr.kek_fingerprint(kek)
        g = groups[fp]
        size = enc.stat().st_size
        out = output_path_for(enc)
        recovered = out.exists()
        folder = enc.relative_to(SRC_ROOT).parts[0] if enc.parent != SRC_ROOT else "<root>"
        ext = original_ext(enc)

        g["total_count"] += 1
        g["total_bytes"] += size
        g["min_fei"] = min(g["min_fei"], fei_len)
        g["max_fei"] = max(g["max_fei"], fei_len)
        g["folders"][folder] += 1
        if recovered:
            g["recovered_count"] += 1
            g["recovered_enc_bytes"] += size
            g["max_recovered_fei"] = max(g["max_recovered_fei"], fei_len)
        else:
            g["remaining_count"] += 1
            g["remaining_bytes"] += size
            g["remaining_exts"][ext] += 1
            g["remaining_ext_bytes"][ext] += size
            g["biggest"].append((size, fei_len, ext, str(enc)))

    rows = []
    for fp, g in groups.items():
        if not g["remaining_count"]:
            continue
        top_exts = ", ".join(
            f"{ext}:{cnt}/{g['remaining_ext_bytes'][ext] / (1024**3):.2f}GB"
            for ext, cnt in g["remaining_exts"].most_common(8)
        )
        rows.append({
            "kek": fp,
            "remaining_gb": g["remaining_bytes"] / (1024**3),
            "remaining_count": g["remaining_count"],
            "recovered_count": g["recovered_count"],
            "total_count": g["total_count"],
            "recovered_file_pct": (g["recovered_count"] * 100.0 / g["total_count"]) if g["total_count"] else 0,
            "min_fei": g["min_fei"],
            "max_fei": g["max_fei"],
            "max_recovered_fei": g["max_recovered_fei"],
            "folders": ";".join(k for k, _ in g["folders"].most_common(6)),
            "top_remaining_exts": top_exts,
            "biggest_file": sorted(g["biggest"], reverse=True)[0][3] if g["biggest"] else "",
        })

    rows.sort(key=lambda r: r["remaining_gb"], reverse=True)
    out_csv = REPORTS / "volume_priority_groups.csv"
    with out_csv.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else [])
        w.writeheader()
        w.writerows(rows)

    print("VOLUME PRIORITY GROUPS")
    print(f"wrote={out_csv}")
    for r in rows[:25]:
        print(
            f"{r['kek']} rem={r['remaining_gb']:.2f}GB files={r['remaining_count']}/"
            f"{r['total_count']} rec={r['recovered_count']} max_rec_fei={r['max_recovered_fei']} "
            f"fei={r['min_fei']}..{r['max_fei']} folders={r['folders']} exts={r['top_remaining_exts']}"
        )
        print(f"  biggest={r['biggest_file']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
