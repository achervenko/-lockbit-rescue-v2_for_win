from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import json
import sys
from pathlib import Path

sys.path[:0] = [
    _project_path(''),
    _project_path('research/legacy'),
]
import lockbit_rescue_v2 as lr
import recover_desktop_tree as rdt

ROOTS = [
    Path(_case_value('970585ac651f2074f264')),
    Path(_case_value('6c2cd6c9e052347de1b2')),
]


def matches_header(p: bytes) -> list[str]:
    hits = []
    patterns = {
        "jpeg": (0, b"\xff\xd8\xff"),
        "png": (0, b"\x89PNG\r\n\x1a\n"),
        "gif87": (0, b"GIF87a"), "gif89": (0, b"GIF89a"),
        "tiff-le": (0, b"II*\x00"), "tiff-be": (0, b"MM\x00*"),
        "bmp": (0, b"BM"), "pdf": (0, b"%PDF-"),
        "zip": (0, b"PK\x03\x04"), "ole": (0, bytes.fromhex("d0cf11e0a1b11ae1")),
        "webp": (0, b"RIFF"), "iso-bmff": (4, b"ftyp"),
        "xml": (0, b"<?xml"),
    }
    for name, (off, magic) in patterns.items():
        if p[off:off + len(magic)] == magic:
            hits.append(name)
    return hits


def main() -> None:
    files = []
    for root in ROOTS:
        for p in root.rglob("*.xzg9VRelb"):
            x = lr.scan_file_worker((str(p.parent), p.name, [".xzg9VRelb"], set(), True))
            if x and x.kek_fingerprint == _case_value('840bb5a427ea610faa0c'):
                files.append(x)
    ks = {}
    for x in sorted(files, key=lambda z: z.coverage, reverse=True):
        b = rdt.run_dump_ks(x)
        if b:
            for i, v in enumerate(b):
                if i not in ks:
                    ks[i] = v
                elif ks[i] != v:
                    raise RuntimeError(f"conflict {i}")
    rdt.learn_name_len_metadata(ks, files)
    rdt.learn_stable_metadata_profiles(ks, files)
    target = next(x for x in files if x.original_name == _case_value('7d817478e11a22b46218'))
    fei_len, _, _, fei_ct, _ = lr.read_fei_ciphertext(Path(target.path))
    start = fei_len - 64
    with Path(target.path).open("rb") as fh:
        enc = fh.read(16)
    hits = []
    for guess in range(65536):
        local = dict(ks)
        local[106] = guess & 0xFF
        local[107] = guess >> 8
        fek = bytes(fei_ct[i] ^ local[i] for i in range(start, fei_len))
        stream = rdt.salsa20_block(fek)
        plain = bytes(a ^ b for a, b in zip(enc, stream))
        kinds = matches_header(plain)
        if kinds:
            hits.append({"guess": f"{guess:04x}", "ks_ext": bytes((guess & 255, guess >> 8)).hex(),
                         "fek": fek.hex(), "plain16": plain.hex(), "kinds": kinds})
    print(json.dumps({"coverage": rdt.contiguous(ks), "hits": hits}, indent=2))


if __name__ == "__main__":
    main()
