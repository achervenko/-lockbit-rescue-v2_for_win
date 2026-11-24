"""Collect historical scripts; keep original case data outside version control."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
RESEARCH = REPO / "research"
SUFFIXES = {".py", ".c", ".h", ".ps1", ".cmd", ".md", ".exe"}
PREAMBLE = '''
# Exported historical experiment. See research/README.md before execution.
import sys as _research_sys
from pathlib import Path as _ResearchPath
_research_root = _ResearchPath(__file__).resolve().parents[1]
for _research_dir in (_research_root, _research_root.parent,
                      _research_root / "legacy", _research_root / "later"):
    _research_sys.path.insert(0, str(_research_dir))
from _research_case import case_value as _case_value, project_path as _project_path
'''


def private_literal(value: str) -> bool:
    return bool(
        re.search(r"[A-Za-z]:[\\/]|\\\\[\w\d]", value)
        or re.fullmatch(r"[0-9a-fA-F]{24,}", value)
        or re.fullmatch(r"[0-9a-fA-F]{12}", value)
        or re.search(r"[^\s/\\]{3,}\.(?:pdf|xlsx?|docx?|pptx?|jpg|jpeg|png|mp4|rar|zip|sldprt|sldasm|slddrw|xzg9VRelb)\b", value, re.I)
    )


def export_python(source: str, values: dict[str, str], paths: dict[str, str]):
    """Replace only complete string expressions, preserving comments and formatting."""
    tree = ast.parse(source)
    parents = {id(child): node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    lines = source.splitlines(keepends=True)
    raw = source.encode("utf-8")
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line.encode("utf-8")))
    edits = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        value = node.value
        if not private_literal(value):
            continue
        parent = parents.get(id(node))
        if isinstance(parent, (ast.JoinedStr, ast.Expr)):
            # JoinedStr constants cannot be replaced by arbitrary expressions.
            # Docstrings are descriptive text; flag suspicious text for review instead.
            continue
        normalized = value.replace("\\", "/").rstrip("/").lower()
        replacement = None
        for prefix, destination in sorted(paths.items(), key=lambda p: -len(p[0])):
            prefix = prefix.replace("\\", "/").rstrip("/").lower()
            if normalized == prefix or normalized.startswith(prefix + "/"):
                suffix = value.replace("\\", "/")[len(prefix):].lstrip("/")
                target = "/".join(part for part in (destination, suffix) if part)
                replacement = f"_project_path({target!r})"
                break
        if replacement is None:
            key = hashlib.sha256(value.encode()).hexdigest()[:20]
            if key in values and values[key] != value:
                raise ValueError("case-value identifier collision")
            values[key] = value
            replacement = f"_case_value({key!r})"
        a = starts[node.lineno - 1] + node.col_offset
        b = starts[node.end_lineno - 1] + node.end_col_offset
        edits.append((a, b, replacement.encode()))
    for a, b, replacement in sorted(edits, reverse=True):
        raw = raw[:a] + replacement + raw[b:]
    result = raw.decode("utf-8")
    tree = ast.parse(result)
    insert_after = 0
    for index, node in enumerate(tree.body):
        if index == 0 and isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            insert_after = node.end_lineno
        elif isinstance(node, ast.ImportFrom) and node.module == "__future__":
            insert_after = node.end_lineno
        else:
            break
    split = result.splitlines(keepends=True)
    result = "".join(split[:insert_after]) + "\n" + PREAMBLE + "\n" + "".join(split[insert_after:])
    ast.parse(result)
    return result, len(edits)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--work", required=True, type=Path)
    ap.add_argument("--later", required=True, type=Path)
    args = ap.parse_args()
    values = {}
    rows = []
    paths = {str(REPO): "", str(args.work): "research/legacy", str(args.later): "research/later"}
    for label, folder in (("legacy", args.work), ("later", args.later)):
        if not folder.is_dir():
            raise FileNotFoundError(folder)
        for path in sorted(folder.iterdir()):
            if not path.is_file() or path.suffix.lower() not in SUFFIXES:
                continue
            local = RESEARCH / "_local" / "originals" / label / path.name
            local.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, local)
            row = {"source": f"{label}/{path.name}", "bytes": path.stat().st_size,
                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                   "public": False, "case_literals": 0}
            if path.suffix == ".py":
                text, replaced = export_python(path.read_text(encoding="utf-8-sig"), values, paths)
                dest = RESEARCH / label / path.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text, encoding="utf-8")
                row.update(public=True, case_literals=replaced)
            elif path.suffix in {".c", ".h"} and path.name not in {"hello.c", "t.c"}:
                text = path.read_text(encoding="utf-8-sig")
                declarations = re.findall(r"static const [^;]+?=\s*\{.*?\};", text, re.S)
                if declarations:
                    text = text.replace(declarations[0], '#include "private_case.h"', 1)
                    for declaration in declarations[1:]:
                        text = text.replace(declaration, "", 1)
                    header = RESEARCH / "_local" / "native" / label / path.stem / "private_case.h"
                    header.parent.mkdir(parents=True, exist_ok=True)
                    header.write_text("\n".join(declarations) + "\n", encoding="utf-8")
                text = re.sub(r'fprintf\(stderr,\s*"target=.*?"\);',
                              lambda _: 'fprintf(stderr, "target=<private case>\\n");', text)
                dest = RESEARCH / "native" / label / path.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(text, encoding="utf-8")
                row.update(public=True, case_literals=len(declarations))
            rows.append(row)
    local_profile = RESEARCH / "_local" / "case_values.json"
    local_profile.write_text(json.dumps(values, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (RESEARCH / "case_values.example.json").write_text(
        json.dumps({k: "REPLACE_WITH_YOUR_CASE_VALUE" for k in values}, indent=2) + "\n", encoding="utf-8")
    (RESEARCH / "inventory.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"originals": len(rows), "public_python": sum(r["public"] for r in rows),
                      "case_values": len(values)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
