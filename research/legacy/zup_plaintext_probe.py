from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


from collections import Counter
from pathlib import Path
import math
import re
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


P = Path(_case_value('3ad29af15411aaf877ae'))
CHUNK = 0x20000
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    good = sum(1 for b in data if b in (9, 10, 13) or 32 <= b <= 126 or b >= 0xC0)
    return good / len(data)


def strings(data: bytes, min_len: int = 6) -> list[str]:
    out = []
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % min_len, data):
        out.append(match.group(0).decode("ascii", errors="replace"))
    return out


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


def is_encrypted_offset(offset: int, ranges: list[tuple[int, int]]) -> bool:
    # Ranges are ordered; linear is fine for this report size.
    for a, b in ranges:
        if a <= offset < b:
            return True
        if a > offset:
            return False
    return False


def main() -> int:
    fei_len, _, body_end, _, _ = lr.read_fei_ciphertext(P)
    ranges = encrypted_ranges(body_end)
    enc_total = sum(b - a for a, b in ranges)
    print(f"body_end={body_end} fei_len={fei_len}")
    print(f"encrypted_ranges={len(ranges)} encrypted_bytes={enc_total} plaintext_bytes_est={body_end - enc_total}")
    print(f"encrypted_percent={enc_total * 100 / body_end:.2f}")
    offsets = [
        0,
        CHUNK,
        2 * CHUNK,
        3 * CHUNK,
        4 * CHUNK,
        0x80000,
        0x100000,
        0x520000,
        0x5A0000,
        0x5C0000,
        0x600000,
        body_end // 2,
        body_end - 0x100000,
        body_end - 0x10000,
    ]
    with P.open("rb") as f:
        for off in offsets:
            if off < 0 or off >= body_end:
                continue
            f.seek(off)
            data = f.read(4096)
            print()
            print(f"OFFSET 0x{off:x} encrypted_region={is_encrypted_offset(off, ranges)} entropy={entropy(data):.3f} printable={printable_ratio(data):.3f}")
            print(f"hex={data[:64].hex()}")
            ss = strings(data[:2048], 8)
            for s in ss[:12]:
                print(f"str={s[:140]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
