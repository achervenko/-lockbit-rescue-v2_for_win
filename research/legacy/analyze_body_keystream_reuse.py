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
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
RANSOM_EXT = ".xzg9VRelb"
PREFIX = 4096


def output_path_for(enc: Path) -> Path:
    rel = enc.relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(RANSOM_EXT)])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    rows = []
    by_stream64 = defaultdict(list)
    by_stream256 = defaultdict(list)

    for enc in SRC_ROOT.rglob(f"*{RANSOM_EXT}"):
        out = output_path_for(enc)
        if not out.exists() or not out.is_file():
            continue
        try:
            fei_len, fei_off, body_end, _, kek = lr.read_fei_ciphertext(enc)
        except Exception:
            continue
        n = min(PREFIX, body_end, out.stat().st_size)
        if n < 64:
            continue
        with enc.open("rb") as f:
            enc_head = f.read(n)
        with out.open("rb") as f:
            dec_head = f.read(n)
        stream = xor_bytes(enc_head, dec_head)
        # Ignore fully unchanged prefixes; those are not useful cipher reuse.
        nonzero = sum(1 for b in stream if b)
        row = {
            "encrypted_path": str(enc),
            "output_path": str(out),
            "kek_fingerprint": lr.kek_fingerprint(kek),
            "fei_len": fei_len,
            "body_end": body_end,
            "sample_len": n,
            "nonzero_xor_bytes": nonzero,
            "stream64_sha256": hashlib.sha256(stream[:64]).hexdigest(),
            "stream256_sha256": hashlib.sha256(stream[:256]).hexdigest() if n >= 256 else "",
            "stream4096_sha256": hashlib.sha256(stream).hexdigest(),
        }
        rows.append(row)
        if nonzero:
            by_stream64[row["stream64_sha256"]].append(row)
            if n >= 256:
                by_stream256[row["stream256_sha256"]].append(row)

    csv_path = REPORTS / "body_keystream_reuse_inventory.csv"
    with csv_path.open("w", newline="", encoding="utf-8-sig") as f:
        fieldnames = list(rows[0].keys()) if rows else []
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    dup64 = {k: v for k, v in by_stream64.items() if len(v) > 1}
    dup256 = {k: v for k, v in by_stream256.items() if len(v) > 1}
    cross_kek64 = [
        (k, v) for k, v in dup64.items()
        if len({r["kek_fingerprint"] for r in v}) > 1
    ]
    cross_kek256 = [
        (k, v) for k, v in dup256.items()
        if len({r["kek_fingerprint"] for r in v}) > 1
    ]

    print("BODY KEYSTREAM REUSE REPORT")
    print(f"pairs_sampled={len(rows)} prefix_bytes={PREFIX}")
    print(f"duplicate_stream64_groups={len(dup64)} cross_kek64_groups={len(cross_kek64)}")
    print(f"duplicate_stream256_groups={len(dup256)} cross_kek256_groups={len(cross_kek256)}")
    for label, groups in [("cross_kek256", cross_kek256[:10]), ("cross_kek64", cross_kek64[:10])]:
        print(label)
        for digest, items in groups:
            print(f"  digest={digest[:16]} count={len(items)} keks={','.join(sorted({r['kek_fingerprint'] for r in items}))}")
            for r in items[:5]:
                print(f"    {r['encrypted_path']}")
    print(f"wrote={csv_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
