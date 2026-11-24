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
import json
import os
import sys
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))
sys.path.insert(0, _project_path('research/legacy'))

import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
DST_ROOT = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST_ROOT / "_technical_reports"
SEED = REPORTS / "sklad_z3_keystream_seed.json"
KEK = _case_value('4906e8c091d91acf1ae1')
TARGET_NAMES = {
    _case_value('ead1978dcb73daa78266'),
    _case_value('ca4654a354defcfd2811'),
    _case_value('48790c62a64487ceaf58'),
    _case_value('5c07ea283dc6dabd8389'),
}
EXT = ".xzg9VRelb"


def load_seed() -> dict[int, int]:
    data = json.loads(SEED.read_text(encoding="utf-8"))
    group = data["groups"][KEK]
    return {int(off): int(byte_hex, 16) for off, byte_hex in group["ks"].items()}


def output_path_for(item: lr.EncryptedFile) -> Path:
    rel = Path(item.path).relative_to(SRC_ROOT)
    return DST_ROOT / Path(str(rel)[: -len(EXT)])


def hex_preview(data: bytes, n: int = 64) -> str:
    return data[:n].hex()


def printable_preview(data: bytes, n: int = 128) -> str:
    out = []
    for b in data[:n]:
        if b in b"\r\n\t":
            out.append({10: "\\n", 13: "\\r", 9: "\\t"}[b])
        elif 32 <= b <= 126:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def encrypted_ranges(body_len: int, before: int = 3, after: int = 3, skipped: int = 0x520000) -> list[tuple[int, int]]:
    # Mirrors direct_decrypt_v2.c behavior: with before=3 it decrypts four
    # chunks before switching to skip because decrement happens after decrypt.
    ranges: list[tuple[int, int]] = []
    cur = 0
    decrypt_remaining = before
    is_skip = False
    chunk = 0x20000
    while cur < body_len:
        if is_skip:
            cur = min(body_len, cur + skipped)
            decrypt_remaining = after
            is_skip = False
            continue
        want = min(chunk, body_len - cur)
        ranges.append((cur, want))
        cur += want
        if decrypt_remaining == 0:
            is_skip = True
        else:
            decrypt_remaining -= 1
    return ranges


def main() -> int:
    REPORTS.mkdir(parents=True, exist_ok=True)
    ks = load_seed()
    groups, _, _ = lr.scan_source(SRC_ROOT / "СКЛАД", [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = groups[KEK]
    rows: list[dict[str, str]] = []
    md: list[str] = []
    md.append("# Разбор gap=11 PDF-пар KEK 624dca208326")
    md.append("")
    md.append(f"Seed coverage: `{rdt.contiguous(ks)}`")
    md.append("")

    selected = [item for item in files if item.original_name in TARGET_NAMES]
    selected.sort(key=lambda item: item.original_name)

    for item in selected:
        enc = Path(item.path)
        out = output_path_for(item)
        fei_len, _, body_end, fei_ct, _ = lr.read_fei_ciphertext(enc)
        plain = out.read_bytes()
        enc_body = enc.read_bytes()[:body_end]
        start = fei_len - 64
        missing_offsets = [off for off in range(start, fei_len) if off not in ks]
        missing_fek_pos = [off - start for off in missing_offsets]
        known_fek = bytearray()
        known_mask = []
        for i in range(64):
            off = start + i
            if off in ks:
                known_fek.append(fei_ct[off] ^ ks[off])
                known_mask.append("K")
            else:
                known_fek.append(0)
                known_mask.append("?")
        body_stream = bytes(a ^ b for a, b in zip(enc_body[: min(len(enc_body), len(plain))], plain))
        ranges = encrypted_ranges(body_end)
        usable_blocks = sum(length for _, length in ranges) // 64
        first_blocks = []
        for block in range(min(8, len(body_stream) // 64)):
            first_blocks.append(body_stream[block * 64 : block * 64 + 16].hex())

        rows.append(
            {
                "filename": item.original_name,
                "encrypted_path": str(enc),
                "plain_path": str(out),
                "fei_len": str(fei_len),
                "body_end": str(body_end),
                "missing_offsets": ",".join(map(str, missing_offsets)),
                "missing_fek_positions": ",".join(map(str, missing_fek_pos)),
                "known_fek_mask": "".join(known_mask),
                "known_fek_zeroed_hex": known_fek.hex(),
                "pdf_prefix_text": printable_preview(plain, 160),
                "pdf_prefix_hex": hex_preview(plain, 160),
                "body_stream_first64": body_stream[:64].hex(),
                "body_stream_block_prefixes": " | ".join(first_blocks),
                "encrypted_ranges_first": "; ".join(f"{off}:{length}" for off, length in ranges[:6]),
                "encrypted_ranges_count": str(len(ranges)),
                "usable_salsa_blocks": str(usable_blocks),
            }
        )

        md.append(f"## {item.original_name}")
        md.append("")
        md.append(f"- encrypted: `{enc}`")
        md.append(f"- plaintext: `{out}`")
        md.append(f"- fei_len/body_end: `{fei_len}` / `{body_end}`")
        md.append(f"- missing FEI offsets: `{','.join(map(str, missing_offsets))}`")
        md.append(f"- missing FEK byte positions: `{','.join(map(str, missing_fek_pos))}`")
        md.append(f"- FEK mask: `{''.join(known_mask)}`")
        md.append(f"- PDF prefix: `{printable_preview(plain, 120)}`")
        md.append(f"- encrypted ranges count: `{len(ranges)}`, usable Salsa20 blocks from pair: `{usable_blocks}`")
        md.append(f"- first encrypted ranges: `{'; '.join(f'{off}:{length}' for off, length in ranges[:6])}`")
        md.append(f"- first body keystream block: `{body_stream[:64].hex()}`")
        md.append("")

    csv_path = REPORTS / "analyze_624_gap11_triplet.csv"
    with csv_path.open("w", encoding="utf-8-sig", newline="") as fh:
        fieldnames = list(rows[0].keys()) if rows else []
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    md.append("## Вывод")
    md.append("")
    md.append(
        "Все три пары имеют один и тот же неизвестный FEI диапазон `106..116`, "
        "который соответствует последним 11 байтам FEK, позициям `53..63`. "
        "Обычный импорт пары не может сам выучить эти байты, потому что для этого "
        "нужно обратить/решить Salsa20. Но каждая пара дает тысячи дополнительных "
        "64-байтных Salsa20-блоков из тела PDF, а не только первый блок. Это главный "
        "следующий путь исследования."
    )
    md_path = REPORTS / "analyze_624_gap11_triplet.md"
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")
    print(csv_path)
    print(md_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
