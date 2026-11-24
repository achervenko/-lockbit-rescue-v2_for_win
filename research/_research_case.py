"""Configuration for exported historical experiments; contains no real case data."""
import json
import os
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def project_path(relative):
    return str(ROOT.parent / relative)


@lru_cache(maxsize=1)
def _values():
    path = Path(os.environ.get("LOCKBIT_CASE_VALUES", ROOT / "case_values.json"))
    if not path.is_file():
        raise RuntimeError(
            "Historical experiment requires a private case profile. "
            "Set LOCKBIT_CASE_VALUES or prepare research/case_values.json; "
            "see research/README.md. Do not publish this profile."
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Case profile must be a JSON object")
    return data


def case_value(key):
    value = _values().get(key)
    if not isinstance(value, str) or value == "REPLACE_WITH_YOUR_CASE_VALUE":
        raise RuntimeError(f"Missing configured case value: {key}")
    return value
