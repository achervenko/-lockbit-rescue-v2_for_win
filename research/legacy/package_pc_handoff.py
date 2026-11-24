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
import shutil
import zipfile
from datetime import datetime
from pathlib import Path


DESKTOP = Path(_case_value('ae6d6877603b6a945206'))
WORK = Path(_project_path('research/legacy'))
REPO = Path(_project_path(''))
ENC_ROOT = DESKTOP / "Зашифрованные файлы"
OUT_ROOT = DESKTOP / "Восстановленные файлы"
REPORTS = OUT_ROOT / "_technical_reports"
PAIR_ROOT = Path(_case_value('793313ad8753ea27fb46'))

STAMP = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
STAGE = DESKTOP / f"lockbit_sklad_pc_handoff_{STAMP}"
ZIP_PATH = DESKTOP / f"lockbit_sklad_pc_handoff_{STAMP}.zip"
EXT = ".xzg9VRelb"


TARGETS = [
    _case_value('f683bce09b3f2fd9d0f7'),
    _case_value('96f97dde841e4b8ae018'),
    _case_value('e937148511a3461677d7'),
    _case_value('9ef1cbfc5457ed16dfbc'),
    _case_value('3d03208a09cc571879e9'),
    _case_value('e937148511a3461677d7'),
    _case_value('94f6e65e03218247907c'),
    _case_value('5fdbc6a617d43b604836'),
]

WORK_FILES = [
    "recover_desktop_tree.py",
    "run_gap6_priority_bruteforce.py",
    "run_gap6_priority_14threads_visible.ps1",
    "make_gap6_bruteforce_4f_fast.py",
    "gap6_bruteforce_4f_fast.c",
    "gap6_bruteforce_4f_fast.exe",
    "deep_fei_analysis_4f.py",
    "solve_sklad_4f_external_pairs_z3.py",
    "solve_sklad_4f_shared_tail_z3.py",
    "solve_tail_fek_z3.py",
    "z3_salsa_word_strategy_4f.py",
    "fei_fek_pattern_research.py",
    "SKLAD_RECOVERY_SUMMARY_RU.md",
]

REPORT_FILES = [
    "gap6_bruteforce_4f_priority_chunks.csv",
    "gap6_bruteforce_4f_priority_state.json",
    "sklad_4f_deep_fei_summary.md",
    "sklad_4f_deep_fei_offsets_108_113.csv",
    "sklad_4f_deep_fei_priority_gaps.csv",
    "sklad_4f_deep_fei_pair_hits.csv",
    "sklad_4f_deep_fei_unknown_bias.csv",
    "SKLAD_IMPLEMENTATION_WEAKNESS_AUDIT_RU.md",
    "sklad_4f_external_pairs_z3.csv",
    "sklad_4f_external_pairs_z3_pairs.csv",
    "sklad_4f_shared_tail_z3.csv",
    "sklad_4f_shared_tail_z3_pairs.csv",
    "sklad_4f_z3_word_strategy.csv",
    "next_recovery_candidate_groups.csv",
    "next_recovery_candidate_files.csv",
    "sklad_best_pair_leverage.csv",
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_file(src: Path, dst: Path, rows: list[dict[str, str]], role: str) -> None:
    if not src.exists() or not src.is_file():
        rows.append({"role": role, "status": "missing", "src": str(src), "dst": str(dst), "size": "", "sha256": ""})
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    rows.append(
        {
            "role": role,
            "status": "copied",
            "src": str(src),
            "dst": str(dst.relative_to(STAGE)),
            "size": str(src.stat().st_size),
            "sha256": sha256(src),
        }
    )


def copy_tree(src: Path, dst: Path, rows: list[dict[str, str]], role: str) -> None:
    if not src.exists():
        rows.append({"role": role, "status": "missing", "src": str(src), "dst": str(dst), "size": "", "sha256": ""})
        return
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        rel = path.relative_to(src)
        if any(part in {".git", "__pycache__", ".pytest_cache", "build", "dist"} for part in rel.parts):
            continue
        copy_file(path, dst / rel, rows, role)


def main() -> int:
    if STAGE.exists():
        shutil.rmtree(STAGE)
    STAGE.mkdir(parents=True)
    rows: list[dict[str, str]] = []

    copy_tree(REPO, STAGE / "repo_lockbit_rescue_v2", rows, "repo")

    for name in WORK_FILES:
        copy_file(WORK / name, STAGE / "work" / name, rows, "work")

    for name in REPORT_FILES:
        copy_file(REPORTS / name, STAGE / "reports" / name, rows, "report")

    research_dir = REPORTS / "fei_fek_research"
    if research_dir.exists():
        copy_tree(research_dir, STAGE / "reports" / "fei_fek_research", rows, "report")

    for rel in dict.fromkeys(TARGETS):
        enc = ENC_ROOT / (rel + EXT)
        copy_file(enc, STAGE / "encrypted_targets" / (rel + EXT), rows, "encrypted_target")
        plain_candidates = [
            OUT_ROOT / rel,
            PAIR_ROOT / Path(rel).name,
        ]
        for idx, plain in enumerate(plain_candidates, 1):
            if plain.exists() and plain.is_file():
                copy_file(plain, STAGE / "known_plaintexts" / Path(rel).name, rows, "known_plaintext")
                break
        else:
            rows.append(
                {
                    "role": "known_plaintext",
                    "status": "missing",
                    "src": " | ".join(map(str, plain_candidates)),
                    "dst": str(Path("known_plaintexts") / Path(rel).name),
                    "size": "",
                    "sha256": "",
                }
            )

    readme = STAGE / "README_RU.md"
    readme.write_text(
        _case_value('67ad3e344b81a8cbcc7c'),
        encoding="utf-8",
    )
    rows.append({"role": "readme", "status": "copied", "src": str(readme), "dst": "README_RU.md", "size": str(readme.stat().st_size), "sha256": sha256(readme)})

    manifest = STAGE / "MANIFEST.csv"
    with manifest.open("w", encoding="utf-8-sig", newline="") as f:
        fields = ["role", "status", "src", "dst", "size", "sha256"]
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    with zipfile.ZipFile(ZIP_PATH, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for path in STAGE.rglob("*"):
            if path.is_file():
                zf.write(path, path.relative_to(STAGE))

    print(f"stage={STAGE}")
    print(f"zip={ZIP_PATH}")
    print(f"zip_size={ZIP_PATH.stat().st_size}")
    copied = sum(1 for row in rows if row["status"] == "copied")
    missing = sum(1 for row in rows if row["status"] == "missing")
    print(f"copied={copied} missing={missing}")
    print(f"manifest={manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
