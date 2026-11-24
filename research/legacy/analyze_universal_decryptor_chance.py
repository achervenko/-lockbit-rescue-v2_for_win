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
import hashlib
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
RANSOM_EXT = ".xzg9VRelb"
ZUP_TARGETS = [
    SRC_ROOT / _case_value('8189fb6a3e572ca31741'),
    REPORTS / "ZUP_archive_extract" / "ZUP" / _case_value('8189fb6a3e572ca31741'),
]


def sha256_prefix(path: Path, size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        remaining = size
        while remaining > 0:
            data = f.read(min(1024 * 1024, remaining))
            if not data:
                break
            h.update(data)
            remaining -= len(data)
    return h.hexdigest()


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(RANSOM_EXT)])


def original_ext(enc: Path) -> str:
    name = enc.name[: -len(RANSOM_EXT)] if enc.name.endswith(RANSOM_EXT) else enc.name
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)

    zup_infos = []
    for zup in ZUP_TARGETS:
        if not zup.exists():
            continue
        z_fei_len, z_fei_off, z_body_end, z_fei_ct, z_kek = lr.read_fei_ciphertext(zup)
        zup_infos.append({
            "path": zup,
            "size": zup.stat().st_size,
            "fei_len": z_fei_len,
            "fei_offset": z_fei_off,
            "body_end": z_body_end,
            "kek_fingerprint": lr.kek_fingerprint(z_kek),
        })
    if not zup_infos:
        raise SystemExit("No ZUP targets found")
    zup_fps = {str(info["kek_fingerprint"]) for info in zup_infos}

    rows = []
    groups: dict[str, list[dict]] = defaultdict(list)
    recovered_groups: dict[str, list[dict]] = defaultdict(list)
    invalid = []

    for enc in SRC_ROOT.rglob(f"*{RANSOM_EXT}"):
        try:
            fei_len, fei_off, body_end, fei_ct, kek = lr.read_fei_ciphertext(enc)
        except Exception as exc:
            invalid.append((str(enc), repr(exc)))
            continue
        fp = lr.kek_fingerprint(kek)
        out = output_path_for(enc)
        recovered = out.exists() and out.is_file()
        row = {
            "encrypted_path": str(enc),
            "output_path": str(out) if recovered else "",
            "folder": enc.relative_to(SRC_ROOT).parts[0] if enc.parent != SRC_ROOT else "<root>",
            "filename": enc.name,
            "original_ext": original_ext(enc),
            "encrypted_size": enc.stat().st_size,
            "recovered_size": out.stat().st_size if recovered else "",
            "fei_len": fei_len,
            "fei_offset": fei_off,
            "body_end": body_end,
            "kek_fingerprint": fp,
            "same_kek_as_zup": fp in zup_fps,
            "recovered": recovered,
            "fei_sha256_16": hashlib.sha256(fei_ct).hexdigest()[:16],
            "kek_sha256_16": hashlib.sha256(kek).hexdigest()[:16],
            "enc_prefix_sha256_16": sha256_prefix(enc)[:16],
            "dec_prefix_sha256_16": sha256_prefix(out)[:16] if recovered else "",
        }
        rows.append(row)
        groups[fp].append(row)
        if recovered:
            recovered_groups[fp].append(row)

    rows_csv = REPORTS / "universal_decryptor_pair_inventory.csv"
    with rows_csv.open("w", newline="", encoding="utf-8-sig") as f:
        fieldnames = list(rows[0].keys()) if rows else []
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    summary_csv = REPORTS / "universal_decryptor_kek_groups.csv"
    with summary_csv.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow([
            "kek_fingerprint",
            "file_count",
            "recovered_count",
            "min_fei_len",
            "max_fei_len",
            "total_encrypted_bytes",
            "folders",
            "same_as_zup",
        ])
        for fp, items in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
            w.writerow([
                fp,
                len(items),
                len(recovered_groups.get(fp, [])),
                min(int(r["fei_len"]) for r in items),
                max(int(r["fei_len"]) for r in items),
                sum(int(r["encrypted_size"]) for r in items),
                ";".join(sorted({str(r["folder"]) for r in items})),
                fp in zup_fps,
            ])

    recovered_total = sum(1 for r in rows if r["recovered"])

    print("UNIVERSAL DECRYPTOR CHANCE REPORT")
    print(f"encrypted_root={SRC_ROOT}")
    print(f"recovered_root={DST_ROOT}")
    print(f"total_encrypted={len(rows)} invalid={len(invalid)} recovered_pairs={recovered_total}")
    print(f"total_kek_groups={len(groups)} recovered_kek_groups={sum(1 for fp in groups if recovered_groups.get(fp))}")
    print()
    print("ZUP TARGETS")
    for info in zup_infos:
        print(f"path={info['path']}")
        print(f"  size={info['size']} kek_fingerprint={info['kek_fingerprint']}")
        print(f"  fei_len={info['fei_len']} fei_offset={info['fei_offset']} body_end={info['body_end']}")
        same_zup = groups.get(str(info["kek_fingerprint"]), [])
        same_zup_recovered = recovered_groups.get(str(info["kek_fingerprint"]), [])
        ext_counter = Counter(str(r["original_ext"]) for r in same_zup)
        print(f"  same_kek_files={len(same_zup)} same_kek_recovered_pairs={len(same_zup_recovered)}")
        print(f"  same_kek_extensions={dict(ext_counter)}")
        for r in same_zup[:20]:
            print(f"    recovered={r['recovered']} fei_len={r['fei_len']} size={r['encrypted_size']} {r['encrypted_path']}")
    print()
    print("TOP KEK GROUPS")
    for fp, items in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))[:20]:
        print(
            f"{fp} files={len(items)} recovered={len(recovered_groups.get(fp, []))} "
            f"fei={min(int(r['fei_len']) for r in items)}..{max(int(r['fei_len']) for r in items)} "
            f"folders={','.join(sorted({str(r['folder']) for r in items})[:4])}"
        )
    print()
    print(f"wrote={rows_csv}")
    print(f"wrote={summary_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
