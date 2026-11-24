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
import os
import re
import sys
from collections import defaultdict
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

EXT = ".xzg9VRelb"
SKLAD_ENC = Path(_case_value('52bfea46a2bd51a621eb'))
REPORT = Path(_case_value('07537fd959126c0f10f8'))

DOWNLOAD_DIRS = [
    Path(_case_value('793313ad8753ea27fb46')),
    Path(_case_value('e405810f2dc0efc537c5')),
    Path(_case_value('4a15d003689fbc67478c')),
    Path(_case_value('6ceb161687bfc8ab8513')),
    Path(_case_value('0f929829e49b11d787e7')),
]

DOC_EXTS = {".pdf", ".docx", ".xlsx", ".xls", ".xlsm", ".doc", ".jpg", ".jpeg", ".png", ".zip"}


def norm_name(name: str) -> str:
    stem = name
    if stem.endswith(EXT):
        stem = stem[: -len(EXT)]
    stem = Path(stem).stem.lower()
    stem = stem.replace("ё", "е")
    stem = re.sub(r"\s*\(\d+\)\s*$", "", stem)
    stem = re.sub(r"[_\-\s.]+", "", stem)
    return stem


def sha256_prefix(path: Path, n: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        h.update(fh.read(n))
    return h.hexdigest()


def main() -> int:
    enc_files = [p for p in SKLAD_ENC.rglob(f"*{EXT}") if p.is_file()]
    enc_by_exact: dict[str, list[Path]] = defaultdict(list)
    enc_by_norm: dict[str, list[Path]] = defaultdict(list)
    enc_by_stem_tokens: list[tuple[Path, set[str]]] = []
    for p in enc_files:
        orig_name = p.name[: -len(EXT)]
        enc_by_exact[orig_name.casefold()].append(p)
        enc_by_norm[norm_name(orig_name)].append(p)
        tokens = set(t for t in re.split(r"[_\-\s().,]+", Path(orig_name).stem.casefold()) if len(t) >= 3)
        enc_by_stem_tokens.append((p, tokens))

    originals: list[Path] = []
    encrypted_in_downloads: list[Path] = []
    for d in DOWNLOAD_DIRS:
        if not d.exists():
            print(f"DIR_MISSING {d}")
            continue
        for p in d.rglob("*"):
            if not p.is_file():
                continue
            if p.name.endswith(EXT):
                encrypted_in_downloads.append(p)
                continue
            if p.suffix.casefold() in DOC_EXTS:
                originals.append(p)

    rows: list[dict[str, str]] = []
    for orig in originals:
        exact = enc_by_exact.get(orig.name.casefold(), [])
        norm = enc_by_norm.get(norm_name(orig.name), [])
        scored: list[tuple[int, Path]] = []
        otokens = set(t for t in re.split(r"[_\-\s().,]+", orig.stem.casefold()) if len(t) >= 3)
        if otokens:
            for enc, etokens in enc_by_stem_tokens:
                score = len(otokens & etokens)
                if score >= 2:
                    scored.append((score, enc))
        candidates: list[tuple[str, Path]] = []
        for p in exact:
            candidates.append(("EXACT_NAME", p))
        for p in norm:
            if p not in exact:
                candidates.append(("NORMALIZED_NAME", p))
        for score, p in sorted(scored, reverse=True)[:5]:
            if all(p != existing for _, existing in candidates):
                candidates.append((f"TOKEN_SCORE_{score}", p))
        for kind, enc in candidates:
            rows.append(
                {
                    "match": kind,
                    "original": str(orig),
                    "original_name": orig.name,
                    "original_size": str(orig.stat().st_size),
                    "original_sha256_1mb": sha256_prefix(orig),
                    "encrypted": str(enc),
                    "encrypted_rel": str(enc.relative_to(SKLAD_ENC)),
                    "encrypted_size": str(enc.stat().st_size),
                }
            )

    same_dir_pairs: list[dict[str, str]] = []
    originals_by_dir_name = {(p.parent, p.name.casefold()): p for p in originals}
    for enc in encrypted_in_downloads:
        orig_name = enc.name[: -len(EXT)]
        orig = originals_by_dir_name.get((enc.parent, orig_name.casefold()))
        if orig:
            same_dir_pairs.append(
                {
                    "match": "SAME_DOWNLOAD_DIR_PAIR",
                    "original": str(orig),
                    "original_name": orig.name,
                    "original_size": str(orig.stat().st_size),
                    "original_sha256_1mb": sha256_prefix(orig),
                    "encrypted": str(enc),
                    "encrypted_rel": "(download-local-pair)",
                    "encrypted_size": str(enc.stat().st_size),
                }
            )

    rows = same_dir_pairs + rows
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    with REPORT.open("w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.DictWriter(
            fh,
            fieldnames=[
                "match",
                "original",
                "original_name",
                "original_size",
                "original_sha256_1mb",
                "encrypted",
                "encrypted_rel",
                "encrypted_size",
            ],
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"DOWNLOAD_ORIGINALS={len(originals)}")
    print(f"DOWNLOAD_ENCRYPTED={len(encrypted_in_downloads)}")
    print(f"MATCH_ROWS={len(rows)}")
    print(f"REPORT={REPORT}")
    for row in rows[:80]:
        print(f"{row['match']}: {row['original_name']} -> {row['encrypted_rel']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
