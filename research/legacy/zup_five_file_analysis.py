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
import subprocess
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
REPORT_DIR = Path(_case_value('4fc7deea4d89b4fa8e6a'))
WORK_OUT = Path(_case_value('73157f0fd94806910136'))
FULL_CANDIDATE = REPORT_DIR / "ZUP_archive_extract" / "ZUP" / _case_value('8189fb6a3e572ca31741')
NAME = "ZUP_backup_2026_08_16_000002_1403489"
RANSOM_EXT = ".xzg9VRelb"
TARGET_KEK = _case_value('c0a199a82c9fb2395448')


@dataclass
class SourceFile:
    label: str
    path: Path
    size: int
    sha256_prefix: str


def sha256_prefix(path: Path, limit: int = 32 * 1024 * 1024) -> str:
    import hashlib

    h = hashlib.sha256()
    remaining = min(path.stat().st_size, limit)
    with path.open("rb") as fh:
        while remaining:
            data = fh.read(min(4 * 1024 * 1024, remaining))
            if not data:
                break
            h.update(data)
            remaining -= len(data)
    return h.hexdigest()


def crc32_file(path: Path) -> str:
    crc = 0
    with path.open("rb") as fh:
        while True:
            data = fh.read(32 * 1024 * 1024)
            if not data:
                break
            crc = zlib.crc32(data, crc)
    return f"{crc & 0xFFFFFFFF:08X}"


def run_7z_list(path: Path) -> str:
    seven = Path(_case_value('0282ba9e3ac325fa22d6'))
    if not seven.exists():
        return "7z.exe not found"
    proc = subprocess.run(
        [str(seven), "l", "-slt", "--", str(path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    return proc.stdout + proc.stderr


def parse_dump_ks(path: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["PATH"] = _case_value('88684c479cc30142395a') + env.get("PATH", "")
    arg = "hex:" + NAME.encode("utf-8").hex()
    proc = subprocess.run(
        [_project_path('brute-extend.exe'), "--dump-ks", str(path), arg],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=120,
    )
    parsed: dict[str, str] = {"returncode": str(proc.returncode), "stderr": proc.stderr.strip()}
    for line in proc.stdout.splitlines():
        if ":" in line:
            key, _, value = line.partition(":")
            parsed[key.strip()] = value.strip()
    return parsed


def encrypted_ranges(body_end: int, before: int = 3, after: int = 3, skipped: int = 0x520000) -> list[tuple[int, int]]:
    chunk = 0x20000
    ranges: list[tuple[int, int]] = []
    cur = 0
    decrypt_remaining = before
    is_skip = False
    while cur < body_end:
        if is_skip:
            cur = min(body_end, cur + skipped)
            decrypt_remaining = after
            is_skip = False
        else:
            end = min(body_end, cur + chunk)
            ranges.append((cur, end))
            cur = end
            if decrypt_remaining == 0:
                is_skip = True
            else:
                decrypt_remaining -= 1
    return ranges


def main() -> int:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    WORK_OUT.mkdir(parents=True, exist_ok=True)

    five_paths = [
        ("first_body_prefix", ROOT / f"{NAME}{RANSOM_EXT}"),
        ("rar_volume_2", ROOT / _case_value('ec20569890b886f12498')),
        ("rar_volume_3", ROOT / _case_value('6ba080f3a73ac9edea14')),
        ("rar_volume_4", ROOT / _case_value('e7827ea57b4616ea5068')),
        ("rar_volume_5", ROOT / _case_value('311e8804ac8235fc2b4a')),
    ]

    sources: list[SourceFile] = []
    missing: list[str] = []
    for label, path in five_paths:
        if not path.exists():
            missing.append(str(path))
            continue
        sources.append(SourceFile(label, path, path.stat().st_size, sha256_prefix(path)))

    full = FULL_CANDIDATE
    full_exists = full.exists()
    prefix_match = False
    if full_exists and five_paths[0][1].exists():
        prefix = five_paths[0][1]
        remaining = prefix.stat().st_size
        prefix_match = True
        with prefix.open("rb") as a, full.open("rb") as b:
            while remaining:
                want = min(8 * 1024 * 1024, remaining)
                da = a.read(want)
                db = b.read(want)
                if da != db:
                    prefix_match = False
                    break
                remaining -= len(da)

    full_facts: dict[str, str] = {}
    if full_exists:
        fei_len, fei_off, body_end, fei, kek = lr.read_fei_ciphertext(full)
        kek_fp = lr.kek_fingerprint(kek)
        dump = parse_dump_ks(full)
        name_len = int(dump.get("NAME_KS_LEN", "0") or "0")
        filename_size = int(dump.get("FILENAME_SIZE", "0") or "0")
        known_with_meta = name_len + 18
        fek_start = fei_len - 64
        ranges = encrypted_ranges(body_end)
        encrypted_bytes = sum(end - start for start, end in ranges)
        full_facts = {
            "full_path": str(full),
            "full_size": str(full.stat().st_size),
            "full_crc32": crc32_file(full),
            "body_end": str(body_end),
            "fei_len": str(fei_len),
            "fei_offset": str(fei_off),
            "kek_fingerprint": kek_fp,
            "name_known_bytes": str(name_len),
            "filename_size_utf16": str(filename_size),
            "known_with_metadata_bytes": str(known_with_meta),
            "fek_start": str(fek_start),
            "fek_end": str(fei_len - 1),
            "unknown_to_fek_start_after_metadata": str(max(0, fek_start - known_with_meta)),
            "unknown_full_fei_after_metadata": str(max(0, fei_len - known_with_meta)),
            "encrypted_chunk_count_default": str(len(ranges)),
            "encrypted_bytes_default": str(encrypted_bytes),
            "encrypted_percent_default": f"{encrypted_bytes * 100 / body_end:.4f}",
        }

    # RAR listing evidence.
    rar_listings: dict[str, str] = {}
    for label, path in five_paths[1:]:
        if path.exists():
            rar_listings[label] = run_7z_list(path)
            (WORK_OUT / f"{label}_7z_list.txt").write_text(rar_listings[label], encoding="utf-8")

    with (WORK_OUT / "zup_five_sources.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["label", "path", "size", "sha256_first_32mb"])
        writer.writeheader()
        for src in sources:
            writer.writerow({
                "label": src.label,
                "path": str(src.path),
                "size": src.size,
                "sha256_first_32mb": src.sha256_prefix,
            })

    with (WORK_OUT / "zup_full_facts.csv").open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(["key", "value"])
        for key, value in full_facts.items():
            writer.writerow([key, value])

    report = [
        "# ZUP Five-File Recovery Analysis",
        "",
        "## Inputs",
        "",
    ]
    for src in sources:
        report.append(f"- `{src.label}`: `{src.path}` ({src.size:,} bytes)")
    if missing:
        report.append("")
        report.append("Missing expected files:")
        report.extend(f"- `{m}`" for m in missing)

    report.extend([
        "",
        "## Archive Reconstruction Check",
        "",
        f"- full assembled candidate exists: `{full_exists}`",
        f"- first 951 MB file is prefix of full candidate: `{prefix_match}`",
    ])
    if full_facts:
        report.extend([
            f"- full CRC32: `{full_facts['full_crc32']}`",
            "- RAR headers report expected CRC32: `BEE32760`",
            f"- CRC match: `{full_facts['full_crc32'] == 'BEE32760'}`",
            "",
            _case_value('05ddc53cb196fd8e0fe8'),
            "",
            "## True LockBit Footer/FEI",
            "",
            f"- full encrypted size: `{full_facts['full_size']}`",
            f"- body size: `{full_facts['body_end']}`",
            f"- FEI length: `{full_facts['fei_len']}`",
            f"- FEI offset: `{full_facts['fei_offset']}`",
            f"- KEK fingerprint: `{full_facts['kek_fingerprint']}`",
            f"- filename-derived FEI plaintext: `{full_facts['name_known_bytes']}` bytes",
            f"- filename + metadata estimate: `{full_facts['known_with_metadata_bytes']}` bytes",
            f"- FEK offsets: `{full_facts['fek_start']}..{full_facts['fek_end']}`",
            f"- unknown bytes to full FEI after metadata: `{full_facts['unknown_full_fei_after_metadata']}`",
            "",
            "## Practical Result",
            "",
            "The five ZUP files are enough to reconstruct and verify the encrypted backup, but they do not contain a second same-KEK oracle or an original/plaintext pair.",
            "",
            "The remaining unknown FEI bytes include the encrypted 64-byte FEK region. Without those FEI keystream bytes, decrypting the first encrypted body chunks is not computationally feasible.",
            "",
            "## Files Written",
            "",
            f"- `{WORK_OUT / 'zup_five_sources.csv'}`",
            f"- `{WORK_OUT / 'zup_full_facts.csv'}`",
            f"- `{WORK_OUT / 'rar_volume_2_7z_list.txt'}`",
            f"- `{WORK_OUT / 'rar_volume_3_7z_list.txt'}`",
            f"- `{WORK_OUT / 'rar_volume_4_7z_list.txt'}`",
            f"- `{WORK_OUT / 'rar_volume_5_7z_list.txt'}`",
        ])

    report_text = "\n".join(report) + "\n"
    report_path = REPORT_DIR / "zup_five_file_recovery_analysis.md"
    report_path.write_text(report_text, encoding="utf-8")
    print(report_text)
    print(f"REPORT={report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
