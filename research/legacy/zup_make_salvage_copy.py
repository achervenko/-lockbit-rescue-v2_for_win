from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


from pathlib import Path
import argparse
import csv
import shutil
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


OUT_DIR = Path(_case_value('c2cb6ef3d173e2cf36a2'))
CHUNK = 0x20000
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000


def encrypted_ranges(body_end: int) -> list[tuple[int, int]]:
    ranges = []
    cur = 0
    decrypt_remaining = BEFORE
    is_skip = False
    while cur < body_end:
        if is_skip:
            cur = min(body_end, cur + SKIPPED)
            decrypt_remaining = AFTER
            is_skip = False
        else:
            end = min(body_end, cur + CHUNK)
            ranges.append((cur, end))
            cur = end
            if decrypt_remaining == 0:
                is_skip = True
            else:
                decrypt_remaining -= 1
    return ranges


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "source",
        nargs="?",
        default=_case_value('3ad29af15411aaf877ae'),
    )
    parser.add_argument("--label", default="ZUP_backup_2026_08_16_000002_1403489")
    args = parser.parse_args()
    src_path = Path(args.source)
    body_out = OUT_DIR / f"{args.label}.body_only_not_decrypted"
    map_out = OUT_DIR / "_technical_reports" / f"{args.label}.encrypted_ranges.csv"

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    map_out.parent.mkdir(parents=True, exist_ok=True)
    fei_len, _, body_end, _, kek = lr.read_fei_ciphertext(src_path)
    ranges = encrypted_ranges(body_end)
    encrypted_total = sum(b - a for a, b in ranges)

    with src_path.open("rb") as src, body_out.open("wb") as dst:
        remaining = body_end
        while remaining:
            chunk = src.read(min(16 * 1024 * 1024, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)

    with map_out.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["start_hex", "end_hex", "start_dec", "end_dec", "length"])
        for start, end in ranges:
            writer.writerow([hex(start), hex(end), start, end, end - start])

    print(f"BODY_OUT={body_out}")
    print(f"MAP_OUT={map_out}")
    print(f"body_end={body_end}")
    print(f"fei_len={fei_len}")
    print(f"kek={lr.kek_fingerprint(kek)}")
    print(f"encrypted_ranges={len(ranges)}")
    print(f"encrypted_bytes={encrypted_total}")
    print(f"encrypted_percent={encrypted_total * 100 / body_end:.2f}")
    print("NOTE=body_only copy is not decrypted; encrypted chunks remain in place")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
