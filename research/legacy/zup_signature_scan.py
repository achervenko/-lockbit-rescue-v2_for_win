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
import bisect
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


P = Path(_case_value('f4560f9e5b634626d7ec'))
CHUNK = 0x20000
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000

SIGS = {
    b"PK\x03\x04": "zip_local",
    b"PK\x05\x06": "zip_eocd",
    b"PK\x01\x02": "zip_cdir",
    b"\x1f\x8b\x08": "gzip",
    b"Rar!\x1a\x07": "rar",
    b"7z\xbc\xaf\x27\x1c": "7z",
    b"SQLite format 3\x00": "sqlite",
    b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1": "ole",
    b"1CDBOBV8": "1cdb_object",
    b"1CDBMSV8": "1cdb_storage",
    b"1CD": "1cd_ascii",
    b"MSSQL": "mssql_ascii",
    b"TAPE": "mssql_tape",
    b"Microsoft SQL Server": "mssql_text",
    b"PostgreSQL": "postgres_text",
    b"PGDMP": "postgres_custom_dump",
}


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


def in_encrypted(offset: int, starts: list[int], ranges: list[tuple[int, int]]) -> bool:
    idx = bisect.bisect_right(starts, offset) - 1
    if idx < 0:
        return False
    start, end = ranges[idx]
    return start <= offset < end


def main() -> int:
    fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(P)
    ranges = encrypted_ranges(body_end)
    starts = [start for start, _ in ranges]
    max_sig = max(len(sig) for sig in SIGS)
    counts: dict[str, int] = {name: 0 for name in SIGS.values()}
    samples: list[tuple[int, str, bool]] = []
    pos = 0
    tail = b""
    with P.open("rb") as f:
        remaining = body_end
        while remaining:
            data = f.read(min(16 * 1024 * 1024, remaining))
            if not data:
                break
            scan = tail + data
            base = pos - len(tail)
            for sig, name in SIGS.items():
                start = 0
                while True:
                    idx = scan.find(sig, start)
                    if idx < 0:
                        break
                    absolute = base + idx
                    if 0 <= absolute < body_end:
                        enc = in_encrypted(absolute, starts, ranges)
                        counts[name] += 1
                        if len(samples) < 200:
                            samples.append((absolute, name, enc))
                    start = idx + 1
            tail = scan[-max_sig + 1 :]
            pos += len(data)
            remaining -= len(data)
    print(f"file={P}")
    print(f"body_end={body_end} fei_len={fei_len}")
    print("COUNTS")
    for name, count in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
        if count:
            print(f"{name}\t{count}")
    print("SAMPLES")
    for absolute, name, enc in samples[:200]:
        print(f"0x{absolute:x}\t{name}\t{'encrypted_range' if enc else 'plain_range'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
