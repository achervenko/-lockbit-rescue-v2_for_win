import ast
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("collector", Path(__file__).with_name("collect_research.py"))
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)

source = '''"""Тест экспорта."""
from __future__ import annotations
from pathlib import Path
ROOT = Path(r"C:\\Users\\sample\\private")
TARGET = "секретный_документ.pdf"
TEXT = "русский текст"; VALUE = "0123456789abcdef0123456789abcdef"
'''
values = {}
exported, count = collector.export_python(source, values, {r"C:\Users\sample\private": "input"})
ast.parse(exported)
assert count == 3
assert "секретный_документ.pdf" not in exported
assert r"C:\Users\sample" not in exported
assert '"русский текст"' in exported
assert "_project_path('input')" in exported
assert len(values) == 2
assert exported.index("from __future__") < exported.index("from _research_case")
extra, _ = collector.export_python('X = r"C:\\repo\\src\\worker.c"\n', {}, {r"C:\repo": ""})
assert "_project_path('src/worker.c')" in extra
print("Collector: Unicode offsets, redaction, paths and future imports PASS")
