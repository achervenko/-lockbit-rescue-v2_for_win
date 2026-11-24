from __future__ import annotations


# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path


import sys
from pathlib import Path

sys.path.insert(0, _project_path(''))
import lockbit_rescue_v2 as lr

import recover_desktop_tree as rdt


SRC = Path(_case_value('f6af7da1ad90629ee69b'))
KEK = _case_value('470c09be6dc8eafece66')
EXT = ".xzg9VRelb"


def main() -> int:
    rdt.SRC = SRC
    groups, _, _ = lr.scan_source(SRC, [EXT], rdt.SCAN_EXTS, False, 1, rdt.MAX_SIZE_BYTES, workers=1)
    files = sorted(groups[KEK], key=lambda f: (f.fei_len, f.original_name.lower()))
    oracle = max(files, key=lambda f: f.coverage)
    ks: dict[int, int] = {}
    for item in sorted(files, key=lambda f: f.coverage, reverse=True):
        more = rdt.run_dump_ks(item)
        if more:
            for off, val in enumerate(more):
                if off not in ks:
                    ks[off] = val
    print("after names", rdt.contiguous(ks))
    print("name_len", rdt.learn_name_len_metadata(ks, files), "cov", rdt.contiguous(ks))
    print("stable_meta", rdt.learn_stable_metadata_profiles(ks, files), "cov", rdt.contiguous(ks))

    learned = 0
    changed = True
    while changed:
        changed = False
        for item in files:
            if not rdt.output_path_for(item).exists():
                continue
            before = rdt.contiguous(ks)
            ok, reason, got = rdt.recover_item(item, oracle, ks, oracle.coverage)
            if ok and got:
                learned += 1
                changed = True
                print("learn_existing", item.fei_len, got, reason, item.original_name, "cov", before, "->", rdt.contiguous(ks))
    print("learned_existing", learned, "cov", rdt.contiguous(ks))

    shown = 0
    for item in files:
        if rdt.output_path_for(item).exists():
            continue
        gap = max(0, item.fei_len - rdt.contiguous(ks))
        ext = rdt.infer_ext(item.original_name)
        if gap > 4 or ext not in {"docx", "pdf", "xlsx"}:
            continue
        ok, reason, got = rdt.recover_item(item, oracle, ks, oracle.coverage)
        print("candidate", "ok" if ok else "fail", "fei", item.fei_len, "gap", gap, "ext", ext, "reason", reason, "learned", got, item.path)
        shown += 1
        if shown >= 50 or ok:
            break
    print("final cov", rdt.contiguous(ks))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
