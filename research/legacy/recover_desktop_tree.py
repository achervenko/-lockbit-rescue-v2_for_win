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
import itertools
import json
import os
import subprocess
import shutil
import sys
import tempfile
import zipfile
import zlib
from collections import Counter
from contextlib import contextmanager
from pathlib import Path

os.environ["PATH"] = _case_value('88684c479cc30142395a') + os.environ.get("PATH", "")
sys.path.insert(0, _project_path(''))

import lockbit_rescue_v2 as lr


SRC_ROOT = Path(_case_value('f6af7da1ad90629ee69b'))
RECOVER_FOLDER = os.environ.get("RECOVER_FOLDER", "АДМИНИСТРАЦИЯ")
SRC = SRC_ROOT / RECOVER_FOLDER
DST = Path(_case_value('c2cb6ef3d173e2cf36a2'))
REPORTS = DST / "_technical_reports"
REPO = Path(_project_path(''))
PACKER = Path(_project_path('research/legacy/aplib_name_pack.exe'))
EXT = ".xzg9VRelb"
BEFORE = 3
AFTER = 3
SKIPPED = 0x520000
MAX_GAP = int(os.environ.get("RECOVER_MAX_GAP", "2"))
BRUTE_TIMEOUT_GAP3_PLUS = int(os.environ.get("RECOVER_BRUTE_TIMEOUT", "60"))
DIRECT_TIMEOUT = int(os.environ.get("RECOVER_DIRECT_TIMEOUT", "120"))
PROGRESS_EVERY = 100
MAX_HELPER_PATH_LEN = 240
VOLUME_PRIORITY = os.environ.get("RECOVER_VOLUME_PRIORITY", "1") != "0"
MAX_SIZE_BYTES = int(float(os.environ.get("RECOVER_MAX_SIZE_GB", "64")) * 1024 * 1024 * 1024)
TARGET_KEK = os.environ.get("RECOVER_TARGET_KEK", "").strip().lower()
TARGET_KEKS = {part.strip().lower() for part in TARGET_KEK.split(",") if part.strip()}
START_BATCH = int(os.environ.get("RECOVER_START_BATCH", "1"))
SKIP_BRUTE = os.environ.get("RECOVER_SKIP_BRUTE", "0") == "1"
USE_LEARNED_PDF_SIGS = os.environ.get("RECOVER_USE_LEARNED_PDF_SIGS", "1") != "0"
LEARNED_PDF_SIGNATURES = REPORTS / "pdf_oracles" / "target_groups" / "target_group_pdf_signatures.json"

EXTRA_MAGIC = {
    # Use container/header prefixes broad enough for real-world variants.
    "pdf": [
        _case_value('e77af2937ada315ae5c4'),
        _case_value('5504214cc0480e2b7b8b'),
        _case_value('2ae27ca9272a44ebdbe0'),
        _case_value('e316b5f91dcb9859424a'),
        _case_value('18417b3afbac856d6509'),
        # bizhub/Konica scanner PDFs often put a DCTDecode Image XObject in the
        # first objects. These ranged signatures give Phase 2 stricter oracles
        # than a bare %PDF header for scanned documents.
        "@512:2f54797065202f584f626a6563740a2f53756274797065202f496d6167650a",
        "@512:2f46696c746572202f4443544465636f64650a",
        "@512:2f42697473506572436f6d706f6e656e7420380a",
        "@512:2f436f6c6f725370616365202f4465766963655247420a",
        "@1024:73747265616d0affd8ff",
        "@2048:2f50726f647563657220284b4f4e494341204d494e4f4c54412062697a687562203333323029",
        "@2048:2f43726561746f72202848617264436f707929",
        "255044462d312e",
        "@64:255044462d",
        "@1024:255044462d",
    ],
    "jpg": ["ffd8ff"],
    "jpeg": ["ffd8ff"],
    "jfif": ["ffd8ff"],
    "pjp": ["ffd8ff", "7b", "5b"],
    "docx": ["504b030414000600", "504b0304"],
    "xlsx": ["504b030414000600", "504b0304"],
    "pptx": ["504b030414000600", "504b0304"],
    "xlsm": ["504b030414000600", "504b0304"],
    "xlsb": ["504b0304", "d0cf11e0a1b11ae1"],
    "vsdx": ["504b0304"],
    "accdb": [_case_value('8a7898acd11b480ecbf0')],
    "url": [_case_value('2b02546434a6a243db96'), "5b7b303030323134"],
    "contact": ["3c3f786d6c"],
    "xml": ["3c3f786d6c"],
    "html": ["3c21444f4354595045", "3c68746d6c", "3c48544d4c"],
    "htm": ["3c21444f4354595045", "3c68746d6c", "3c48544d4c"],
    "thmx": ["504b0304"],
    "dwg": ["41433130"],
    # Some old Word .doc files are saved as Word-compatible HTML.
    "doc": ["d0cf11e0a1b11ae1", "3c68746d6c", "3c48544d4c"],
    "lnk": ["4c00000001140200"],
    "msg": ["d0cf11e0a1b11ae1"],
    "msi": ["d0cf11e0a1b11ae1"],
    "md5": ["30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "61", "62", "63", "64", "65", "66"],
    "dav": ["44484156"],
    "dxf": [_case_value('03ded90105c1141bcb60'), "2020300a53454354494f4e", "300a53454354494f4e"],
    "txt": ["efbbbf", "5b", "23", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39"],
    "log": ["efbbbf", "5b", "23", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39"],
    "css": ["2f2a", "2e", "23", "40"],
    "bat": ["40", "65", "72", "3a", "63", "43", "52", "63"],
    "inf": ["5b56657273696f6e5d", "3b", "5b"],
    "json": ["7b", "5b"],
    "loc": ["efbbbf", "fffe", "feff", "3c", "5b", "7b"],
    "txts": ["efbbbf", "fffe", "feff", "3c", "5b", "7b", "30", "31", "32"],
    "ttme": ["efbbbf", "fffe", "feff", "3c", "5b", "7b", "30", "31", "32"],
    "pj": ["efbbbf", "fffe", "feff", "3c", "5b", "7b", "30", "31", "32"],
    "png": ["89504e470d0a1a0a"],
    "xps": ["504b0304"],
    "rar": ["526172211a0700", "526172211a070100", _case_value('3a0b3bec9ccafa7a208c')],
    "rtf": [_case_value('55a209dc47d70760e15d')],
    # Detached electronic signatures in this tree are usually DER/CMS blobs.
    "sig": ["3082", "30"],
    "cat": ["3082", "30"],
    "dl_": ["4d534346", "535a4444"],
    "ex_": ["4d534346", "535a4444"],
    "ca_": ["4d534346", "535a4444"],
    "ch_": ["4d534346", "535a4444"],
    "djvu": ["41542654464f524d"],
    "ai": ["255044462d", "252150532d41646f6265"],
    # macOS Spotlight metadata stores; mostly technical, but include them so
    # remaining-file analysis accounts for copied Mac folders.
    "shadow": ["38747364", "00"],
    "directorystorefile": ["00", "38747364"],
    "indexarrays": ["00", "38747364"],
    "indexbigdates": ["00", "38747364"],
    "indexcompactdirectory": ["00", "38747364"],
    "indexdirectory": ["00", "38747364"],
    "indexgroups": ["00", "38747364"],
    "indexhead": ["00", "38747364"],
    "indexids": ["00", "38747364"],
    "indexpositions": ["00", "38747364"],
    "indexpositiontable": ["00", "38747364"],
    "indexpostings": ["00", "38747364"],
    "indextermids": ["00", "38747364"],
    "shadowindexarrays": ["00", "38747364"],
    "shadowindexcompactdirectory": ["00", "38747364"],
    "shadowindexdirectory": ["00", "38747364"],
    "shadowindexgroups": ["00", "38747364"],
    "shadowindexhead": ["00", "38747364"],
    "shadowindextermids": ["00", "38747364"],
    "updates": ["00", "38747364"],
    "state": ["00", "38747364"],
    "plist": [_case_value('f9f6b82cd86712740b2f'), "3c3f786d6c"],
    # Temporary files can be saved Office/PDF/image containers with a .tmp name.
    "tmp": ["255044462d", "504b0304", "d0cf11e0a1b11ae1", "89504e470d0a1a0a", "ffd8ff"],
    # SolidWorks files are OLE Compound File Binary in this dataset/family.
    "sldprt": ["d0cf11e0a1b11ae1"],
    "sldasm": ["d0cf11e0a1b11ae1"],
    "slddrw": ["d0cf11e0a1b11ae1"],
    # STEP/STP are text files with a stable ISO-10303 prefix.
    "stp": [_case_value('f27b00682657e9475f46')],
    "step": [_case_value('f27b00682657e9475f46')],
    # Microsoft Project is OLE Compound File Binary.
    "mpp": ["d0cf11e0a1b11ae1"],
    # AutoCAD/CAD backups in this tree are usually DWG or Office/PDF backups.
    "bak": ["41433130", "d0cf11e0a1b11ae1", "504b0304", "255044462d"],
    # ACIS SAT models are plain text, commonly starting with a version line.
    "sat": ["37303020", "34303020", "41434953"],
    "sth_a": ["00", "efbbbf", "fffe", "feff"],
}
lr.MAGIC_DATABASE.update(EXTRA_MAGIC)
SCAN_EXTS = set(lr.DEFAULT_COMMON_EXTS) | set(EXTRA_MAGIC)
SCAN_EXTS.update({"iso", "dav", "lnk", "partial"})


def infer_ext(original_name: str) -> str:
    parts = [part.lower() for part in original_name.split(".")[1:]]
    if not parts:
        return ""
    ext = parts[-1]
    if ext != "partial":
        return ext
    for part in reversed(parts[:-1]):
        if part in SCAN_EXTS and part != "partial":
            return part
    return ext


def magic_candidates(ext: str) -> list[str]:
    ext = ext.lower()
    if not ext:
        return [
            "255044462d312e",  # PDF
            "504b0304",        # ZIP / Office
            "d0cf11e0a1b11ae1", # OLE / MSG / XLS
            "ffd8ff",          # JPEG
            "89504e470d0a1a0a", # PNG
        ]
    if ext in {"mp4", "mov", "m4v"}:
        sizes = list(range(8, 65, 4))
        # Try the most common box sizes first; the rest cover camera variants.
        preferred = [0x18, 0x14, 0x20, 0x1C, 0x10, 0x0C, 0x24, 0x28, 0x30, 0x38, 0x40]
        ordered = preferred + [s for s in sizes if s not in preferred]
        return [s.to_bytes(4, "big").hex() + "66747970" for s in ordered]
    if ext == "exe":
        # MZ is short, but strict PE validation below rejects false positives.
        return ["4d5a"]
    if ext == "iso":
        # ISO9660/UDF has no useful offset-0 magic. A zero byte prefix allows
        # FEK probing; strict validation checks CD001 at sector descriptors.
        return ["00"]
    magics = lr.MAGIC_DATABASE.get(ext)
    if magics:
        return [lr.hex_clean(m) for m in magics if m]
    magic = lr.get_magic_for_extension(ext)
    return [magic] if magic else []


_LEARNED_PDF_MAGIC_CACHE: dict[str, list[str]] | None = None


def learned_pdf_magic_by_kek() -> dict[str, list[str]]:
    """Load deterministic PDF signatures learned from recovered same-KEK pairs."""
    global _LEARNED_PDF_MAGIC_CACHE
    if _LEARNED_PDF_MAGIC_CACHE is not None:
        return _LEARNED_PDF_MAGIC_CACHE
    out: dict[str, list[str]] = {}
    if not USE_LEARNED_PDF_SIGS or not LEARNED_PDF_SIGNATURES.exists():
        _LEARNED_PDF_MAGIC_CACHE = out
        return out
    try:
        data = json.loads(LEARNED_PDF_SIGNATURES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _LEARNED_PDF_MAGIC_CACHE = out
        return out

    for kek, group in data.get("groups", {}).items():
        sample_count = int(group.get("sample_count") or 0)
        if sample_count < 3:
            continue
        magics: list[str] = []
        for sig in group.get("signatures", []):
            spec = str(sig.get("magic_spec") or "")
            if not spec:
                continue
            fraction = float(sig.get("fraction") or 0)
            # Keep perfect signatures, plus the RGB/gray branch signatures. Very
            # long embedded JPEG tables are skipped because brute-extend uses
            # short probes and long probes only slow the search down.
            hex_part = spec.split(":", 1)[1] if spec.startswith("@") else spec
            if len(lr.hex_clean(hex_part)) // 2 > 64:
                continue
            if fraction < 0.30:
                continue
            magics.append(spec)
        out[kek.lower()] = magics[:16]
    _LEARNED_PDF_MAGIC_CACHE = out
    return out


def magic_candidates_for_item(item: lr.EncryptedFile, ext: str, kek: str = "") -> list[str]:
    magics: list[str] = []
    if ext.lower() == "pdf" and kek:
        magics.extend(learned_pdf_magic_by_kek().get(kek.lower(), []))
    magics.extend(magic_candidates(ext))

    seen: set[str] = set()
    deduped: list[str] = []
    for magic in magics:
        key = magic.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(magic)
    return deduped


def detect_recovered_ext(path: Path, fallback_ext: str) -> str:
    if fallback_ext:
        return fallback_ext
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if data.startswith(b"%PDF-") and b"%%EOF" in data[-8192:]:
        return "pdf"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
            if "[Content_Types].xml" in names and any(name.startswith("xl/") for name in names):
                return "xlsx"
            if "[Content_Types].xml" in names and any(name.startswith("word/") for name in names):
                return "docx"
            return "zip"
        except (OSError, zipfile.BadZipFile):
            return ""
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "ole"
    if data.startswith(b"\xff\xd8\xff") and data.rstrip().endswith(b"\xff\xd9"):
        return "jpg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    return ""


@contextmanager
def helper_path(path: str | Path, prefix: str):
    src = Path(path)
    needs_helper = len(str(src)) >= MAX_HELPER_PATH_LEN or any(ord(ch) > 127 for ch in str(src))
    if not needs_helper:
        yield src
        return
    with tempfile.TemporaryDirectory(prefix=f"{prefix}_") as td:
        suffix = "".join(ch if ch.isascii() and ch.isalnum() else "_" for ch in src.suffix)
        tmp = Path(td) / f"{prefix}_input{suffix}"
        shutil.copy2(src, tmp)
        yield tmp


def parse_out(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            out[k.strip()] = v.strip()
    return out


def run_dump_ks(item: lr.EncryptedFile) -> bytes | None:
    import subprocess

    arg = "hex:" + item.original_name.encode("utf-8").hex()
    with helper_path(item.path, "oracle") as oracle_path:
        result = subprocess.run(
            [str(REPO / "brute-extend.exe"), "--dump-ks", str(oracle_path), arg],
            capture_output=True,
            text=True,
            timeout=120,
        )
    parsed = parse_out(result.stdout)
    if result.returncode != 0 or parsed.get("STATUS") != "OK_DUMP":
        return None
    return bytes.fromhex(parsed["KS"])


def pack_known_names(names: list[str], mode: str = "") -> list[bytes | None]:
    if not PACKER.exists():
        return [None] * len(names)
    args = ["hex:" + name.encode("utf-8").hex() for name in names]
    cmd = [str(PACKER), "--batch"]
    if mode:
        cmd.append(mode)
    try:
        result = subprocess.run(
            cmd,
            input="\n".join(args) + "\n",
            capture_output=True,
            text=True,
            timeout=max(30, len(names) // 50 + 30),
        )
    except Exception:
        return [None] * len(names)
    out: list[bytes | None] = []
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) != 4 or parts[0] != "OK":
            out.append(None)
            continue
        try:
            out.append(bytes.fromhex(parts[3]))
        except ValueError:
            out.append(None)
    if len(out) < len(names):
        out.extend([None] * (len(names) - len(out)))
    return out[: len(names)]


def build_name_ks_from_packer(files: list[lr.EncryptedFile]) -> tuple[dict[int, int], int, int, int, str]:
    best: tuple[dict[int, int], int, int, int, str] = ({}, 0, 0, 0, "PACKER_NONE")
    for mode in ("", "workmem-final"):
        ks: dict[int, int] = {}
        dumps = 0
        learned = 0
        conflicts = 0
        packed = pack_known_names([item.original_name for item in files], mode)
        for item, blob in zip(files, packed):
            if blob is None or len(blob) != item.coverage:
                continue
            try:
                _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
            except Exception:
                continue
            dumps += 1
            for off, plain in enumerate(blob):
                old = ks.get(off)
                val = fei_ct[off] ^ plain
                if old is not None and old != val:
                    conflicts += 1
                    continue
                if old is None:
                    learned += 1
                ks[off] = val
        label = "PACKER_BASENAME" if not mode else "PACKER_BASENAME_WORKMEM"
        current = (ks, dumps, learned, conflicts, label)
        if (conflicts, -contiguous(ks), -dumps) < (best[3], -contiguous(best[0]), -best[1]):
            best = current
    return best


def merge_ks(ks: dict[int, int], offset: int, value: int) -> bool:
    old = ks.get(offset)
    if old is not None and old != value:
        return False
    ks[offset] = value
    return True


def contiguous(ks: dict[int, int]) -> int:
    i = 0
    while i in ks:
        i += 1
    return i


def ks_ext_hex(ks: dict[int, int], base: int, cov: int) -> str:
    if cov <= base:
        return ""
    return bytes(ks[i] for i in range(base, cov)).hex()


def chunking_params_for(item: lr.EncryptedFile, ks: dict[int, int]) -> tuple[int, int, int, str]:
    """Read per-file intermittent encryption parameters from FEI metadata.

    FEI layout after the compressed filename:
    [compressed filename len u16][skipped u64][before u32][after u32].
    The global sparse keystream often covers this small range from longer
    filenames in the same KEK batch; video files depend on these values.
    """
    base = item.coverage
    if all(off in ks for off in range(base, base + 18)):
        try:
            _, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
            dec = bytes(fei_ct[off] ^ ks[off] for off in range(base, base + 18))
            name_len = int.from_bytes(dec[0:2], "little")
            skipped = int.from_bytes(dec[2:10], "little")
            before = int.from_bytes(dec[10:14], "little")
            after = int.from_bytes(dec[14:18], "little")
            sane = (
                name_len == item.coverage
                and 0 < skipped <= MAX_SIZE_BYTES
                and skipped % 0x20000 == 0
                and 0 <= before <= 4096
                and 0 <= after <= 4096
            )
            if sane:
                return before, after, skipped, "FEI_PARAMS"
        except Exception:
            pass
    return BEFORE, AFTER, SKIPPED, "DEFAULT_PARAMS"


def learn_fek(ks: dict[int, int], item: lr.EncryptedFile, fek_hex: str) -> int:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    fek = bytes.fromhex(lr.hex_clean(fek_hex))
    start = fei_len - 64
    learned = 0
    for i, b in enumerate(fek):
        off = start + i
        val = fei_ct[off] ^ b
        existed = off in ks
        if merge_ks(ks, off, val) and not existed:
            learned += 1
    return learned


def learn_name_len_metadata(ks: dict[int, int], files: list[lr.EncryptedFile]) -> tuple[int, int, int]:
    """Learn deterministic FEI bytes: uint16 compressed filename length.

    The 18-byte metadata block starts immediately after the compressed
    filename. Its first field is the compressed filename length, which is
    already known as item.coverage. Learn only offsets where all candidates
    agree; conflicted offsets are left untouched.
    """
    candidates: dict[int, set[int]] = {}
    sources = 0
    for item in files:
        try:
            fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        off = item.coverage
        if off + 2 > fei_len or off + 2 > len(fei_ct):
            continue
        plain = int(item.coverage).to_bytes(2, "little")
        for idx, plain_byte in enumerate(plain):
            ks_off = off + idx
            candidates.setdefault(ks_off, set()).add(fei_ct[ks_off] ^ plain_byte)
        sources += 1

    learned = 0
    conflicts = 0
    for off, values in sorted(candidates.items()):
        if len(values) != 1:
            conflicts += 1
            continue
        value = next(iter(values))
        old = ks.get(off)
        if old is not None and old != value:
            conflicts += 1
            continue
        if old is None:
            ks[off] = value
            learned += 1
    return learned, conflicts, sources


def stable_metadata_plaintext(item: lr.EncryptedFile) -> bytes | None:
    ext = infer_ext(item.original_name)
    # Confirmed from 22k+ recovered metadata rows. Video/container media use
    # several chunking profiles, so do not infer them here.
    stable_default_exts = {
        "jpg", "jpeg", "jfif", "png", "webp",
        "pdf", "doc", "docx", "rtf", "xls", "xlsx", "xlsb", "xlsm",
        "ppt", "pptx", "msg", "url", "xml", "html", "htm", "txt",
        "zip", "rar", "7z", "sldprt", "sldasm", "slddrw", "stp", "step",
    }
    if ext not in stable_default_exts:
        return None
    try:
        size = Path(item.path).stat().st_size
    except OSError:
        return None
    # Very large archives occasionally switch to a video-like profile; skip
    # them unless verified by recovered FEI bytes.
    if ext in {"zip", "rar", "7z"} and size >= 100 * 1024 * 1024:
        return None
    return (
        int(item.coverage).to_bytes(2, "little")
        + int(SKIPPED).to_bytes(8, "little")
        + int(BEFORE).to_bytes(4, "little")
        + int(AFTER).to_bytes(4, "little")
    )


def learn_stable_metadata_profiles(ks: dict[int, int], files: list[lr.EncryptedFile]) -> tuple[int, int, int]:
    candidates: dict[int, set[int]] = {}
    sources = 0
    for item in files:
        plain = stable_metadata_plaintext(item)
        if plain is None:
            continue
        try:
            fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
        except Exception:
            continue
        off = item.coverage
        if off + len(plain) > fei_len or off + len(plain) > len(fei_ct):
            continue
        for idx, plain_byte in enumerate(plain):
            ks_off = off + idx
            candidates.setdefault(ks_off, set()).add(fei_ct[ks_off] ^ plain_byte)
        sources += 1

    learned = 0
    conflicts = 0
    for off, values in sorted(candidates.items()):
        if len(values) != 1:
            conflicts += 1
            continue
        value = next(iter(values))
        old = ks.get(off)
        if old is not None and old != value:
            conflicts += 1
            continue
        if old is None:
            ks[off] = value
            learned += 1
    return learned, conflicts, sources


def derive_fek_from_ks(ks: dict[int, int], item: lr.EncryptedFile) -> str | None:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    start = fei_len - 64
    if start < 0:
        return None
    fek = bytearray()
    for off in range(start, start + 64):
        if off not in ks:
            return None
        fek.append(fei_ct[off] ^ ks[off])
    return bytes(fek).hex()


def _rotl32(value: int, shift: int) -> int:
    return ((value << shift) & 0xFFFFFFFF) | (value >> (32 - shift))


def salsa20_block(key: bytes) -> bytes:
    state = [int.from_bytes(key[i * 4 : i * 4 + 4], "little") for i in range(16)]
    work = state[:]
    for _ in range(10):
        work[4] ^= _rotl32((work[0] + work[12]) & 0xFFFFFFFF, 7)
        work[8] ^= _rotl32((work[4] + work[0]) & 0xFFFFFFFF, 9)
        work[12] ^= _rotl32((work[8] + work[4]) & 0xFFFFFFFF, 13)
        work[0] ^= _rotl32((work[12] + work[8]) & 0xFFFFFFFF, 18)
        work[9] ^= _rotl32((work[5] + work[1]) & 0xFFFFFFFF, 7)
        work[13] ^= _rotl32((work[9] + work[5]) & 0xFFFFFFFF, 9)
        work[1] ^= _rotl32((work[13] + work[9]) & 0xFFFFFFFF, 13)
        work[5] ^= _rotl32((work[1] + work[13]) & 0xFFFFFFFF, 18)
        work[14] ^= _rotl32((work[10] + work[6]) & 0xFFFFFFFF, 7)
        work[2] ^= _rotl32((work[14] + work[10]) & 0xFFFFFFFF, 9)
        work[6] ^= _rotl32((work[2] + work[14]) & 0xFFFFFFFF, 13)
        work[10] ^= _rotl32((work[6] + work[2]) & 0xFFFFFFFF, 18)
        work[3] ^= _rotl32((work[15] + work[11]) & 0xFFFFFFFF, 7)
        work[7] ^= _rotl32((work[3] + work[15]) & 0xFFFFFFFF, 9)
        work[11] ^= _rotl32((work[7] + work[3]) & 0xFFFFFFFF, 13)
        work[15] ^= _rotl32((work[11] + work[7]) & 0xFFFFFFFF, 18)
        work[1] ^= _rotl32((work[0] + work[3]) & 0xFFFFFFFF, 7)
        work[2] ^= _rotl32((work[1] + work[0]) & 0xFFFFFFFF, 9)
        work[3] ^= _rotl32((work[2] + work[1]) & 0xFFFFFFFF, 13)
        work[0] ^= _rotl32((work[3] + work[2]) & 0xFFFFFFFF, 18)
        work[6] ^= _rotl32((work[5] + work[4]) & 0xFFFFFFFF, 7)
        work[7] ^= _rotl32((work[6] + work[5]) & 0xFFFFFFFF, 9)
        work[4] ^= _rotl32((work[7] + work[6]) & 0xFFFFFFFF, 13)
        work[5] ^= _rotl32((work[4] + work[7]) & 0xFFFFFFFF, 18)
        work[11] ^= _rotl32((work[10] + work[9]) & 0xFFFFFFFF, 7)
        work[8] ^= _rotl32((work[11] + work[10]) & 0xFFFFFFFF, 9)
        work[9] ^= _rotl32((work[8] + work[11]) & 0xFFFFFFFF, 13)
        work[10] ^= _rotl32((work[9] + work[8]) & 0xFFFFFFFF, 18)
        work[12] ^= _rotl32((work[15] + work[14]) & 0xFFFFFFFF, 7)
        work[13] ^= _rotl32((work[12] + work[15]) & 0xFFFFFFFF, 9)
        work[14] ^= _rotl32((work[13] + work[12]) & 0xFFFFFFFF, 13)
        work[15] ^= _rotl32((work[14] + work[13]) & 0xFFFFFFFF, 18)
    return b"".join(((work[i] + state[i]) & 0xFFFFFFFF).to_bytes(4, "little") for i in range(16))


def recover_fek_from_known_pair(item: lr.EncryptedFile, ks: dict[int, int]) -> str | None:
    plain_path = output_path_for(item)
    if not plain_path.exists():
        return None
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    try:
        _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
        if plain_path.stat().st_size != body_end:
            return None
    except OSError:
        return None
    start = fei_len - 64
    if start < 0:
        return None
    missing = [off for off in range(start, fei_len) if off not in ks]
    if len(missing) > 2:
        return None
    with Path(item.path).open("rb") as enc_fh, plain_path.open("rb") as plain_fh:
        enc_head = enc_fh.read(64)
        plain_head = plain_fh.read(64)
    if len(enc_head) < 16 or len(plain_head) != len(enc_head):
        return None
    expected = bytes(a ^ b for a, b in zip(enc_head, plain_head))
    for guess in itertools.product(range(256), repeat=len(missing)):
        local = dict(ks)
        for off, val in zip(missing, guess):
            local[off] = val
        fek = bytes(fei_ct[start + i] ^ local[start + i] for i in range(64))
        if salsa20_block(fek)[: len(expected)] == expected:
            return fek.hex()
    return None


def recover_fek_from_magic_python(item: lr.EncryptedFile, ks: dict[int, int], magics: list[str]) -> str | None:
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(item.path))
    start = fei_len - 64
    if start < 0:
        return None
    missing = [off for off in range(start, fei_len) if off not in ks]
    if not missing or len(missing) > 2:
        return None
    try:
        with Path(item.path).open("rb") as enc_fh:
            enc_head = enc_fh.read(64)
    except OSError:
        return None
    if len(enc_head) < 16:
        return None

    magic_bytes = [bytes.fromhex(lr.hex_clean(magic)) for magic in magics if not magic.startswith("@")]
    for guess in itertools.product(range(256), repeat=len(missing)):
        local = dict(ks)
        for off, val in zip(missing, guess):
            local[off] = val
        fek = bytes(fei_ct[start + i] ^ local[start + i] for i in range(64))
        keyblock = salsa20_block(fek)
        for magic in magic_bytes:
            test_len = min(len(magic), len(enc_head), 16)
            if test_len and bytes(a ^ b for a, b in zip(enc_head[:test_len], keyblock[:test_len])) == magic[:test_len]:
                return fek.hex()
    return None


def output_path_for(item: lr.EncryptedFile) -> Path:
    enc = Path(item.path)
    rel = enc.relative_to(SRC_ROOT)
    rel_no_ext = Path(str(rel)[: -len(EXT)])
    rename_parts = {"�11_inf": "М11_inf", "���_inf": "ЭДО_inf", "�11": "М11", "���": "ЭДО"}
    rel_no_ext = Path(*[rename_parts.get(part, part) for part in rel_no_ext.parts])
    out = DST / rel_no_ext
    if not infer_ext(rel_no_ext.name) and not out.exists():
        for detected in ("pdf", "xlsx", "docx", "zip", "ole", "jpg", "png"):
            typed = out.with_suffix("." + detected)
            if typed.exists():
                return typed
    return out


def encrypted_size(item: lr.EncryptedFile) -> int:
    try:
        return Path(item.path).stat().st_size
    except OSError:
        return 0


def batch_remaining_bytes(files: list[lr.EncryptedFile]) -> int:
    return sum(encrypted_size(item) for item in files if not output_path_for(item).exists())


def recovery_order(files: list[lr.EncryptedFile], ks: dict[int, int], learned_existing: set[str]) -> list[lr.EncryptedFile]:
    cov = contiguous(ks)

    def key(item: lr.EncryptedFile) -> tuple[int, int, int, int, str]:
        out_exists = output_path_for(item).exists()
        gap = max(0, item.fei_len - cov)
        if out_exists and item.path in learned_existing:
            learned_rank = 2
        elif out_exists:
            learned_rank = 1
        else:
            learned_rank = 0
        if not VOLUME_PRIORITY:
            return (learned_rank, gap, item.fei_len, -encrypted_size(item), item.original_name.lower())
        return (learned_rank, gap, -encrypted_size(item), item.fei_len, item.original_name.lower())

    return sorted(files, key=key)


def validate_recovered(path: Path, ext: str) -> bool:
    ext = ext.lower()
    if ext == "pdf":
        try:
            data = path.read_bytes()
        except OSError:
            return False
        if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-8192:]:
            return False
        if b"startxref" not in data[-16384:] and b"xref" not in data[-65536:]:
            return False
        return True
    if ext in {"txt", "log", "css", "bat", "inf", "json", "loc", "txts", "ttme", "pj"}:
        try:
            data = path.read_bytes()[:65536]
        except OSError:
            return False
        if not data:
            return False
        if ext == "json":
            stripped = data.lstrip()
            return stripped.startswith((b"{", b"["))
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            return True
        printable = sum(1 for b in data if b in b"\t\r\n" or 32 <= b <= 126 or b >= 0x80)
        return printable / len(data) > 0.90
    if ext == "dav":
        try:
            head = path.read_bytes()[:16]
        except OSError:
            return False
        return head.startswith(b"DHAV")
    if ext == "dxf":
        try:
            head = path.read_bytes()[:4096].lower()
        except OSError:
            return False
        return b"section" in head and (head.lstrip().startswith(b"0") or head.startswith(b"  0"))
    if ext in {"stp", "step"}:
        try:
            head = path.read_bytes()[:4096].upper()
        except OSError:
            return False
        return head.startswith(b"ISO-10303-21;") or b"HEADER;" in head[:512]
    if ext == "sat":
        try:
            data = path.read_bytes()[:65536]
        except OSError:
            return False
        if not data:
            return False
        head = data[:512].lower()
        printable = sum(1 for b in data if b in b"\t\r\n" or 32 <= b <= 126 or b >= 0x80)
        return printable / len(data) > 0.90 and (b"acis" in head or head[:4] in {b"700 ", b"400 "})
    if ext == "png":
        try:
            head = path.read_bytes()[:64]
        except OSError:
            return False
        if len(head) < 33 or head[:8] != b"\x89PNG\r\n\x1a\n":
            return False
        if head[8:16] != b"\x00\x00\x00\rIHDR":
            return False
        return zlib.crc32(head[12:29]).to_bytes(4, "big") == head[29:33]
    if ext == "jfif":
        try:
            data = path.read_bytes()
        except OSError:
            return False
        return len(data) > 16 and data.startswith(b"\xff\xd8\xff") and data.rstrip().endswith(b"\xff\xd9")
    if ext in {"sig", "cat"}:
        try:
            data = path.read_bytes()[:16]
        except OSError:
            return False
        return len(data) >= 4 and data[0] == 0x30 and data[1] in {0x80, 0x81, 0x82, 0x83}
    if ext in {"dl_", "ex_", "ca_", "ch_"}:
        try:
            head = path.read_bytes()[:8]
        except OSError:
            return False
        return head.startswith(b"MSCF") or head.startswith(b"SZDD")
    if ext == "djvu":
        try:
            head = path.read_bytes()[:16]
        except OSError:
            return False
        return head.startswith(b"AT&TFORM")
    if ext == "accdb":
        try:
            head = path.read_bytes()[:32]
        except OSError:
            return False
        return head.startswith(bytes.fromhex(_case_value('8a7898acd11b480ecbf0')))
    if ext == "ai":
        try:
            head = path.read_bytes()[:64]
        except OSError:
            return False
        return head.startswith(b"%PDF-") or head.startswith(b"%!PS-Adobe")
    if ext == "rar":
        try:
            head = path.read_bytes()[:16]
        except OSError:
            return False
        return head.startswith(b"Rar!\x1a\x07\x00") or head.startswith(b"Rar!\x1a\x07\x01\x00")
    if ext == "lnk":
        try:
            head = path.read_bytes()[:76]
        except OSError:
            return False
        link_clsid = bytes.fromhex(_case_value('14b93c44cd3440ba87c6'))
        return len(head) >= 76 and head[:4] == b"L\x00\x00\x00" and head[4:20] == link_clsid
    if ext in {"doc", "msg", "mpp", "sldprt", "sldasm", "slddrw"}:
        try:
            head = path.read_bytes()[:512]
        except OSError:
            return False
        if len(head) >= 512 and head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return True
        if ext == "doc":
            text = head.lower().lstrip()
            return text.startswith(b"<html") or text.startswith(b"<!doctype html") or b"urn:schemas-microsoft-com:office:office" in text
        return False
    if ext == "bak":
        try:
            data = path.read_bytes()[:65536]
        except OSError:
            return False
        if not data:
            return False
        if data.startswith(b"AC10"):
            return True
        if data.startswith(b"%PDF-"):
            try:
                return b"%%EOF" in path.read_bytes()[-4096:]
            except OSError:
                return False
        if data.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(path) as zf:
                    return bool(zf.namelist())
            except (OSError, zipfile.BadZipFile):
                return False
        if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return True
        printable = sum(1 for b in data if b in b"\t\r\n" or 32 <= b <= 126 or b >= 0x80)
        return printable / len(data) > 0.92
    if ext == "sth_a":
        try:
            data = path.read_bytes()[:65536]
        except OSError:
            return False
        if not data:
            return False
        printable = sum(1 for b in data if b in b"\t\r\n" or 32 <= b <= 126 or b >= 0x80)
        return printable / len(data) > 0.92
    if ext in {"mp4", "mov", "m4v"}:
        try:
            head = path.read_bytes()[:1024 * 1024]
        except OSError:
            return False
        if len(head) < 16 or head[4:8] != b"ftyp":
            return False
        box_size = int.from_bytes(head[:4], "big")
        if box_size < 8 or box_size > 4096:
            return False
        brands = {b"isom", b"iso2", b"mp41", b"mp42", b"qt  ", b"M4V ", b"3gp4", b"avc1", b"MSNV"}
        return any(brand in head[8:128] for brand in brands)
    if ext == "exe":
        try:
            head = path.read_bytes()[:4096]
        except OSError:
            return False
        if len(head) < 0x40 or head[:2] != b"MZ":
            return False
        pe_off = int.from_bytes(head[0x3C:0x40], "little")
        return 0 < pe_off < len(head) - 4 and head[pe_off:pe_off + 4] == b"PE\x00\x00"
    if ext == "iso":
        try:
            with path.open("rb") as f:
                for sector in range(16, 32):
                    f.seek(sector * 2048 + 1)
                    if f.read(5) in {b"CD001", b"BEA01", b"NSR02", b"NSR03", b"TEA01"}:
                        return True
        except OSError:
            return False
        return False
    if ext in {"xlsm", "xlsb", "vsdx", "odt", "xps"}:
        try:
            with zipfile.ZipFile(path) as zf:
                names = set(zf.namelist())
        except (OSError, zipfile.BadZipFile):
            return False
        if ext in {"xlsm", "xlsb"}:
            return "[Content_Types].xml" in names and any(n.startswith("xl/") for n in names)
        if ext == "vsdx":
            return "[Content_Types].xml" in names and any(n.startswith("visio/") for n in names)
        if ext == "xps":
            return "[Content_Types].xml" in names and any(n.startswith("Documents/") or n.startswith("FixedDoc") for n in names)
        return "mimetype" in names and any(n.startswith("content.xml") or n.endswith("/content.xml") for n in names)
    if ext == "url":
        try:
            head = path.read_bytes()[:4096].decode("utf-8-sig", errors="ignore")
        except OSError:
            return False
        normalized = head.replace("\r\n", "\n").replace("\r", "\n")
        stripped = normalized.lstrip()
        return (
            stripped.startswith("[InternetShortcut]") and "\nURL=" in normalized
        ) or (
            stripped.startswith('[{"000214') and ("http" in stripped.lower() or "url" in stripped.lower())
        )
    if ext in {"htm", "html"}:
        try:
            data = path.read_bytes()[:65536]
        except OSError:
            return False
        if data.startswith((b"\xff\xfe", b"\xfe\xff")):
            text = data.decode("utf-16le" if data.startswith(b"\xff\xfe") else "utf-16be", errors="ignore").lower()
            return "<html" in text or "<!doctype html" in text
        text = data.decode("utf-8-sig", errors="ignore").lower()
        return "<html" in text or "<!doctype html" in text
    if ext == "xml":
        try:
            text = path.read_bytes()[:65536].decode("utf-8-sig", errors="ignore").lower()
        except OSError:
            return False
        stripped = text.lstrip()
        return stripped.startswith("<?xml") or stripped.startswith("<xml") or stripped.startswith("<")
    if ext == "pjp":
        try:
            data = path.read_bytes()[:65536]
        except OSError:
            return False
        if data.startswith(b"\xff\xd8\xff"):
            return validate_recovered(path, "jfif")
        stripped = data.lstrip()
        return stripped.startswith((b"{", b"[")) or sum(1 for b in data if b in b"\t\r\n" or 32 <= b <= 126 or b >= 0x80) / max(1, len(data)) > 0.90
    if ext == "contact":
        try:
            head = path.read_bytes()[:4096].decode("utf-8-sig", errors="ignore").lower()
        except OSError:
            return False
        return head.startswith("<?xml") and "<c:contact" in head
    if ext == "tmp":
        try:
            head = path.read_bytes()[:4096]
        except OSError:
            return False
        if head.startswith(b"%PDF-"):
            return b"%%EOF" in path.read_bytes()[-4096:]
        if head.startswith(b"PK\x03\x04"):
            try:
                with zipfile.ZipFile(path) as zf:
                    return bool(zf.namelist())
            except (OSError, zipfile.BadZipFile):
                return False
        if head.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
            return True
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return validate_recovered(path, "png")
        if head.startswith(b"\xff\xd8\xff"):
            return validate_recovered(path, "jfif")
        return False
    return lr.validate_decryption_with_magic(path, ext)


def direct_decrypt_with_timeout(
    direct_bin: Path,
    target_path: Path,
    output_path: Path,
    fek_hex: str,
    before_chunk: int,
    after_chunk: int,
    skipped_hex: str,
) -> bool:
    cmd = [
        str(direct_bin),
        str(target_path),
        str(output_path),
        fek_hex,
        str(before_chunk),
        str(after_chunk),
        skipped_hex,
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=DIRECT_TIMEOUT)
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0 and output_path.exists() and output_path.stat().st_size > 0


def try_alternative_chunk_params(item: lr.EncryptedFile, fek_hex: str, ext: str, output_path: Path) -> bool:
    """Try a small set of observed chunk parameter variants.

    A few recovered PDFs in new folders had a valid FEK but failed strict
    validation with FEI/default chunk parameters. Keep this list deliberately
    short so normal runs do not turn into broad parameter sweeps.
    """
    candidates = [
        (0, 0, 0x100000),
        # DarkSide-family samples encrypt 0x80000-byte blocks and then jump
        # according to mode/size. LockBit/BagIRA samples usually differ, but
        # trying these is cheap after a FEK is already known and can rescue
        # files whose FEI chunk metadata was not recovered correctly.
        (0, 0, 0x80000),
        (1, 1, 0x80000),
        (2, 2, 0x80000),
        (3, 3, 0x80000),
        (3, 0, 0x20000),
        (3, 0, 0x200000),
        (0, 0, 0x520000),
        (2, 2, 0x520000),
        (3, 3, 0x520000),
    ]
    for before, after, skipped in candidates:
        with tempfile.TemporaryDirectory(prefix="recover_tree_alt_") as td:
            tmp = Path(td) / "dec"
            with helper_path(item.path, "direct_alt") as direct_path:
                ok = direct_decrypt_with_timeout(
                    REPO / "direct-decrypt.exe",
                    direct_path,
                    tmp,
                    fek_hex,
                    before,
                    after,
                    hex(skipped),
                )
            if ok and validate_recovered(tmp, ext):
                output_path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, output_path)
                return True
    return False


def recover_item(item: lr.EncryptedFile, oracle: lr.EncryptedFile, ks: dict[int, int], base_cov: int, kek: str = "") -> tuple[bool, str, int]:
    if not Path(item.path).exists():
        return False, "source_missing", 0
    if not Path(oracle.path).exists():
        return False, "oracle_missing", 0

    ext = infer_ext(item.original_name)
    magics = magic_candidates_for_item(item, ext, kek)
    if not magics:
        return False, "no_magic", 0

    cov = contiguous(ks)
    gap = max(0, item.fei_len - cov)
    if gap > MAX_GAP:
        return False, f"gap_{gap}", 0
    before, after, skipped, params_source = chunking_params_for(item, ks)

    tried = 0
    fek_hex = None
    method_suffix = ""
    if gap == 0:
        fek_hex = derive_fek_from_ks(ks, item)
        method_suffix = "_FEI_KS"
    if not fek_hex:
        fek_hex = recover_fek_from_known_pair(item, ks)
        if fek_hex:
            method_suffix = "_KNOWN_PAIR_BODY"
    if not fek_hex and gap > 0:
        fek_hex = recover_fek_from_magic_python(item, ks, magics)
        if fek_hex:
            method_suffix = "_PY_MAGIC"
    if not fek_hex and gap > 0 and not SKIP_BRUTE:
        result = None
        with helper_path(item.path, "target") as target_path, helper_path(oracle.path, "oracle") as oracle_path:
            for magic in magics:
                tried += 1
                result = lr.brute_extend_target(
                    REPO / "brute-extend.exe",
                    target_path,
                    oracle_path,
                    oracle.original_name,
                    magic,
                    gap,
                    before,
                    after,
                    hex(skipped),
                    ks_ext_hex(ks, base_cov, cov),
                    timeout=BRUTE_TIMEOUT_GAP3_PLUS if gap >= 3 else 180,
                )
                if result and result.get("FEK"):
                    break
        if result and result.get("FEK"):
            fek_hex = lr.hex_clean(result["FEK"])
        if tried > 1:
            method_suffix = "_MULTIMAGIC"
    if not fek_hex:
        return False, f"no_fek_gap_{gap}", 0

    with tempfile.TemporaryDirectory(prefix="recover_tree_") as td:
        tmp = Path(td) / "dec"
        with helper_path(item.path, "direct") as direct_path:
            ok = direct_decrypt_with_timeout(
                REPO / "direct-decrypt.exe",
                direct_path,
                tmp,
                fek_hex,
                before,
                after,
                hex(skipped),
            )
        if not ok:
            out = output_path_for(item)
            if not out.exists() and try_alternative_chunk_params(item, fek_hex, ext, out):
                method_suffix += "_ALT_CHUNKING"
            else:
                return False, "direct_failed", 0
        else:
            out = output_path_for(item)
        detected_ext = detect_recovered_ext(tmp, ext) if ok else ext
        validate_ext = detected_ext or ext
        if ok and validate_ext and validate_recovered(tmp, validate_ext):
            if detected_ext and not ext:
                out = out.with_suffix("." + detected_ext)
            if not out.exists():
                out.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(tmp, out)
        elif ok and not out.exists() and try_alternative_chunk_params(item, fek_hex, ext, out):
            method_suffix += "_ALT_CHUNKING"
        elif ok:
            return False, "strict_validation_failed", 0

    learned = learn_fek(ks, item, fek_hex)
    method = "PHASE1_DIRECT" if gap == 0 else f"PHASE2_BRUTE_{gap}"
    method += method_suffix
    if params_source != "DEFAULT_PARAMS":
        method += "_FEI_CHUNKING"
    return True, method, learned


def learn_existing_item(item: lr.EncryptedFile, oracle: lr.EncryptedFile, ks: dict[int, int], base_cov: int, kek: str = "") -> tuple[bool, str, int]:
    """Learn FEI keystream from an already restored output without re-decrypting it.

    Resume runs used to call recover_item(), which decrypts and strictly validates
    the whole file again. That is wasteful for large files; for learning we only
    need a verified FEK, then learn_fek() adds the corresponding FEI bytes.
    """
    out = output_path_for(item)
    if not out.exists() or not Path(item.path).exists() or not Path(oracle.path).exists():
        return False, "existing_missing", 0

    try:
        _, _, body_end, _, _ = lr.read_fei_ciphertext(Path(item.path))
        if out.stat().st_size != body_end:
            return False, "existing_size_mismatch", 0
    except OSError:
        return False, "existing_read_failed", 0

    ext = infer_ext(item.original_name)
    magics = magic_candidates_for_item(item, ext, kek)
    if not magics:
        return False, "no_magic", 0

    cov = contiguous(ks)
    gap = max(0, item.fei_len - cov)
    if gap > MAX_GAP:
        return False, f"gap_{gap}", 0

    before, after, skipped, _ = chunking_params_for(item, ks)
    fek_hex = None
    method_suffix = ""
    if gap == 0:
        fek_hex = derive_fek_from_ks(ks, item)
        method_suffix = "_FEI_KS"
    if not fek_hex:
        fek_hex = recover_fek_from_known_pair(item, ks)
        if fek_hex:
            method_suffix = "_KNOWN_PAIR_BODY"
    if not fek_hex and gap > 0:
        fek_hex = recover_fek_from_magic_python(item, ks, magics)
        if fek_hex:
            method_suffix = "_PY_MAGIC"
    if not fek_hex and gap > 0 and not SKIP_BRUTE:
        result = None
        with helper_path(item.path, "target") as target_path, helper_path(oracle.path, "oracle") as oracle_path:
            for magic in magics:
                result = lr.brute_extend_target(
                    REPO / "brute-extend.exe",
                    target_path,
                    oracle_path,
                    oracle.original_name,
                    magic,
                    gap,
                    before,
                    after,
                    hex(skipped),
                    ks_ext_hex(ks, base_cov, cov),
                    timeout=BRUTE_TIMEOUT_GAP3_PLUS if gap >= 3 else 180,
                )
                if result and result.get("FEK"):
                    break
        if result and result.get("FEK"):
            fek_hex = lr.hex_clean(result["FEK"])
            method_suffix = "_BRUTE_EXISTING"
    if not fek_hex:
        return False, f"no_fek_gap_{gap}", 0

    learned = learn_fek(ks, item, fek_hex)
    return True, "LEARN_EXISTING" + method_suffix, learned


def main() -> int:
    DST.mkdir(parents=True, exist_ok=True)
    REPORTS.mkdir(parents=True, exist_ok=True)
    groups, scanned, skipped = lr.scan_source(
        SRC, [EXT], SCAN_EXTS, True, 1, MAX_SIZE_BYTES, workers=1
    )
    if TARGET_KEKS:
        groups = {k: v for k, v in groups.items() if k.lower() in TARGET_KEKS}
    print(f"SCANNED files={scanned} groups={len(groups)} skipped={skipped}", flush=True)

    rows: list[dict[str, str]] = []
    totals = Counter()

    def batch_sort_key(kv: tuple[str, list[lr.EncryptedFile]]) -> tuple[int, int]:
        files = kv[1]
        if VOLUME_PRIORITY:
            return (batch_remaining_bytes(files), len(files))
        return (len(files), batch_remaining_bytes(files))

    for batch_no, (kek, files) in enumerate(sorted(groups.items(), key=batch_sort_key, reverse=True), 1):
        if batch_no < START_BATCH:
            continue
        files = sorted(files, key=lambda f: (f.fei_len, f.original_name.lower()))
        ks: dict[int, int] = {}

        oracle = None
        name_ks = None
        for candidate in sorted(files, key=lambda f: f.coverage, reverse=True):
            name_ks = run_dump_ks(candidate)
            if name_ks:
                oracle = candidate
                break
        if oracle is None or not name_ks:
            packer_ks, packer_dumps, packer_learned, packer_conflicts, packer_label = build_name_ks_from_packer(files)
            if not packer_ks:
                print(f"BATCH {batch_no}/{len(groups)} {kek}: cannot dump oracle ks", flush=True)
                continue
            oracle = max(files, key=lambda f: f.coverage)
            base_cov = 0
            ks.update(packer_ks)
            name_dumps = packer_dumps
            name_learned = packer_learned
            name_conflicts = packer_conflicts
            print(
                f"BATCH {batch_no}/{len(groups)} {kek}: using {packer_label} fallback "
                f"name_dumps={name_dumps} name_cov={contiguous(ks)} conflicts={name_conflicts}",
                flush=True,
            )
        else:
            base_cov = oracle.coverage
            for off, val in enumerate(name_ks):
                ks[off] = val

            name_dumps = 1
            name_learned = 0
            name_conflicts = 0

            for name_item in sorted(files, key=lambda f: f.coverage, reverse=True):
                if name_item.path == oracle.path:
                    continue
                try:
                    more_ks = run_dump_ks(name_item)
                except Exception:
                    continue
                if more_ks is None:
                    continue
                name_dumps += 1
                for off, val in enumerate(more_ks):
                    existed = off in ks
                    if merge_ks(ks, off, val):
                        if not existed:
                            name_learned += 1
                    else:
                        name_conflicts += 1

        meta_learned, meta_conflicts, meta_sources = learn_name_len_metadata(ks, files)
        stable_meta_learned, stable_meta_conflicts, stable_meta_sources = learn_stable_metadata_profiles(ks, files)
        print(
            f"BATCH {batch_no}/{len(groups)} kek={kek} count={len(files)} oracle_fei={oracle.fei_len} "
            f"base_cov={base_cov} start_cov={contiguous(ks)} name_dumps={name_dumps} "
            f"name_learned={name_learned} name_conflicts={name_conflicts} "
            f"meta_len_sources={meta_sources} meta_len_learned={meta_learned} "
            f"meta_len_conflicts={meta_conflicts} stable_meta_sources={stable_meta_sources} "
            f"stable_meta_learned={stable_meta_learned} stable_meta_conflicts={stable_meta_conflicts} "
            f"oracle='{oracle.original_name}'",
            flush=True,
        )

        existing_in_batch = 0
        for item in files:
            out = output_path_for(item)
            if out.exists():
                existing_in_batch += 1
                rows.append({
                    "status": "SUCCESS",
                    "method": "SKIPPED_EXISTS",
                    "kek": kek,
                    "fei_len": str(item.fei_len),
                    "encrypted_path": item.path,
                    "output_path": str(out),
                })
        if existing_in_batch:
            print(f"  resume: already_have={existing_in_batch}", flush=True)

        recovered_in_batch = 0
        learned_existing_in_batch = 0
        learned_existing: set[str] = set()
        failed_attempts: dict[str, int] = {}
        failure_reasons = Counter()

        rebuild_progress = True
        while rebuild_progress:
            rebuild_progress = False
            for item in files:
                cov_now = contiguous(ks)
                if item.path in learned_existing or failed_attempts.get(item.path) == cov_now:
                    continue
                if not output_path_for(item).exists():
                    continue
                ok, reason, learned = learn_existing_item(item, oracle, ks, base_cov, kek)
                if ok:
                    learned_existing.add(item.path)
                    learned_existing_in_batch += 1
                    rebuild_progress = True
                    if learned_existing_in_batch % PROGRESS_EVERY == 0:
                        print(
                            f"  progress learned_existing={learned_existing_in_batch} cov={contiguous(ks)}",
                            flush=True,
                        )
                elif not reason.startswith("gap_"):
                    failed_attempts[item.path] = cov_now
                    failure_reasons[reason] += 1

        progressed = True
        while progressed:
            progressed = False
            for item in recovery_order(files, ks, learned_existing):
                out = output_path_for(item)
                existed_before = out.exists()
                if existed_before and item.path in learned_existing:
                    continue
                cov_now = contiguous(ks)
                if failed_attempts.get(item.path) == cov_now:
                    continue
                if existed_before:
                    ok, reason, learned = learn_existing_item(item, oracle, ks, base_cov, kek)
                else:
                    ok, reason, learned = recover_item(item, oracle, ks, base_cov, kek)
                if ok:
                    if existed_before:
                        learned_existing.add(item.path)
                        learned_existing_in_batch += 1
                    else:
                        recovered_in_batch += 1
                        totals["ok"] += 1
                    progressed = True
                    if not existed_before and recovered_in_batch % PROGRESS_EVERY == 0:
                        print(
                            f"  progress recovered_new={recovered_in_batch} cov={contiguous(ks)} "
                            f"last_fei={item.fei_len}",
                            flush=True,
                        )
                    if existed_before and learned_existing_in_batch % PROGRESS_EVERY == 0:
                        print(
                            f"  progress learned_existing={learned_existing_in_batch} cov={contiguous(ks)}",
                            flush=True,
                        )
                    if not existed_before:
                        rows.append({
                            "status": "SUCCESS",
                            "method": reason,
                            "kek": kek,
                            "fei_len": str(item.fei_len),
                            "encrypted_path": item.path,
                            "output_path": str(output_path_for(item)),
                        })
                elif reason.startswith("gap_"):
                    continue
                else:
                    failed_attempts[item.path] = cov_now
                    failure_reasons[reason] += 1

        remaining = sum(1 for item in files if not output_path_for(item).exists())
        for item in files:
            if output_path_for(item).exists():
                continue
            gap = max(0, item.fei_len - contiguous(ks))
            rows.append({
                "status": "FAILED",
                "method": f"NOT_RECOVERED_GAP_{gap}",
                "kek": kek,
                "fei_len": str(item.fei_len),
                "encrypted_path": item.path,
                "output_path": str(output_path_for(item)),
            })
        print(
            f"BATCH_DONE kek={kek} recovered={recovered_in_batch} learned_existing={learned_existing_in_batch} "
            f"remaining={remaining} final_cov={contiguous(ks)} failures={dict(failure_reasons.most_common(8))}",
            flush=True,
        )

    safe_name = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in RECOVER_FOLDER.lower())
    manifest = REPORTS / f"recovery_manifest_{safe_name}_latest.csv"
    with manifest.open("w", encoding="utf-8-sig", newline="") as fh:
        fields = ["status", "method", "kek", "fei_len", "encrypted_path", "output_path"]
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"DONE ok={totals['ok']} manifest={manifest}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
