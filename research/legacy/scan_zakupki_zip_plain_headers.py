from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import os
import sys
from pathlib import Path

os.environ["RECOVER_FOLDER"] = "ЗАКУПКИ"
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt
from analyze_auto_remaining import build_group_keystream
from solve_zakupki_mp4_body_constraints_z3 import encrypted_windows, overlaps_windows


ENC_ROOT = Path(_case_value('8df57692b42e1f6f68e0'))
OUT_ROOT = Path(_case_value('6bd784b051ab83e84361'))
EXT = ".xzg9VRelb"


def out_rel_for(enc: Path) -> Path:
    return Path(str(enc.relative_to(ENC_ROOT))[: -len(EXT)])


def in_window(pos: int, wins: list[tuple[int, int]]) -> bool:
    return any(s <= pos < e for s, e in wins)


def scan_local_headers(data: bytes, wins: list[tuple[int, int]]) -> list[tuple[int, str, int, int, int, bool]]:
    hits = []
    pos = 0
    while True:
        pos = data.find(b"PK\x03\x04", pos)
        if pos < 0:
            break
        if pos + 30 <= len(data):
            flags = int.from_bytes(data[pos + 6:pos + 8], "little")
            method = int.from_bytes(data[pos + 8:pos + 10], "little")
            comp = int.from_bytes(data[pos + 18:pos + 22], "little")
            uncomp = int.from_bytes(data[pos + 22:pos + 26], "little")
            nlen = int.from_bytes(data[pos + 26:pos + 28], "little")
            xlen = int.from_bytes(data[pos + 28:pos + 30], "little")
            if 0 < nlen < 300 and pos + 30 + nlen + xlen <= len(data):
                name = data[pos + 30:pos + 30 + nlen].decode("utf-8", "replace")
                sane = "/" in name or name.endswith(".xml") or name == "[Content_Types].xml"
                encrypted = in_window(pos, wins) or overlaps_windows(pos, pos + 30 + nlen + xlen + comp, wins)
                if sane:
                    hits.append((pos, name, flags, method, comp, encrypted))
        pos += 4
    return hits


def main() -> int:
    groups, _, _ = lr.scan_source(ENC_ROOT, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    for kek, files in groups.items():
        ks = build_group_keystream(files)
        for item in files:
            enc = Path(item.path)
            rel = out_rel_for(enc)
            if rel.suffix.lower().lstrip(".") not in {"docx", "xlsx"}:
                continue
            if (OUT_ROOT / rel).exists():
                continue
            _, _, body_end, _, _ = lr.read_fei_ciphertext(enc)
            data = enc.read_bytes()[:body_end]
            before, after, skipped, source = rdt.chunking_params_for(item, ks)
            wins = encrypted_windows(body_end, before, after, skipped)
            hits = scan_local_headers(data, wins)
            plain = [h for h in hits if not h[-1]]
            enc_hits = [h for h in hits if h[-1]]
            print(f"rel={rel} kek={kek} size={body_end} params={before}/{after}/0x{skipped:x}/{source} hits={len(hits)} plain={len(plain)} enc={len(enc_hits)}")
            for h in plain[:30]:
                print(f"  plain off={h[0]} name={h[1]} flags=0x{h[2]:x} method={h[3]} comp={h[4]}")
            for h in enc_hits[:10]:
                print(f"  enc off={h[0]} name={h[1]} flags=0x{h[2]:x} method={h[3]} comp={h[4]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
