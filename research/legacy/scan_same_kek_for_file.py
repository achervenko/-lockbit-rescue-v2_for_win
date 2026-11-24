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
import sys

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("roots", nargs="+")
    args = parser.parse_args()
    target = Path(args.target)
    _, _, _, _, target_kek = lr.read_fei_ciphertext(target)
    fp = lr.kek_fingerprint(target_kek)
    rows = []
    scanned = 0
    for root_s in args.roots:
        root = Path(root_s)
        for path in root.rglob("*.xzg9VRelb"):
            scanned += 1
            try:
                fei_len, _, _, _, kek = lr.read_fei_ciphertext(path)
            except Exception:
                continue
            if lr.kek_fingerprint(kek) == fp:
                rows.append((fei_len, path.stat().st_size, path))
    print(f"target={target}")
    print(f"target_kek={fp} scanned={scanned} same_kek={len(rows)}")
    for fei_len, size, path in sorted(rows, key=lambda row: (-row[0], -row[1], str(row[2]).lower()))[:500]:
        print(f"{fei_len}\t{size}\t{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
