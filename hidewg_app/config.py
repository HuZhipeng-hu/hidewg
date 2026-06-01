from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


def _parse_scalar(raw: str) -> Any:
    value = raw.strip()
    if not value:
        return ""
    if value[0:1] in ("'", '"') and value[-1:] == value[0]:
        return value[1:-1]
    lowered = value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    if lowered in {"null", "none"}:
        return None
    if value.startswith("[") and value.endswith("]"):
        try:
            return ast.literal_eval(value)
        except (SyntaxError, ValueError):
            return [item.strip() for item in value[1:-1].split(",") if item.strip()]
    try:
        return int(value, 0)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        return value


def load_config(path: str | Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    config_path = Path(path)
    text = config_path.read_text(encoding="utf-8")
    if config_path.suffix.lower() == ".json":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(f"{config_path} must contain a JSON object")
        return data

    data: dict[str, Any] = {}
    for line_no, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            # Only strip comments that aren't inside quoted values
            _, colon, value_part = stripped.partition(":")
            if colon and value_part:
                v = value_part.strip()
                if not (v.startswith('"') or v.startswith("'")):
                    stripped = stripped.split("#", 1)[0].rstrip()
        if ":" not in stripped:
            raise ValueError(f"{config_path}:{line_no}: expected key: value")
        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        if not key:
            raise ValueError(f"{config_path}:{line_no}: empty key")
        data[key] = _parse_scalar(raw_value)
    return data


def as_int(config: dict[str, Any], key: str, default: int) -> int:
    value = config.get(key, default)
    if isinstance(value, str):
        return int(value, 0)
    return int(value)


def as_float(config: dict[str, Any], key: str, default: float) -> float:
    return float(config.get(key, default))


def as_list(config: dict[str, Any], key: str, default: list[int]) -> list[int]:
    value = config.get(key, default)
    if isinstance(value, str):
        return [int(item.strip(), 0) for item in value.split(",") if item.strip()]
    return [int(item) for item in value]
