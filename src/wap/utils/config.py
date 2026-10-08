from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[3]  # writeup_attck_pipeline/


_ENV_PATTERN = re.compile(r"\$\{([^}:]+)(?::-([^}]*))?\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):

        def repl(m: re.Match[str]) -> str:
            key, default = m.group(1), m.group(2)
            return os.environ.get(key, default if default is not None else "")

        return _ENV_PATTERN.sub(repl, value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def load_yaml(path: Path | str) -> dict[str, Any]:
    p = Path(path)
    if not p.is_absolute():
        p = ROOT / p
    with p.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return _expand_env(data)


def resolve_path(path: str | Path) -> Path:
    p = Path(path)
    if p.is_absolute():
        return p
    return (ROOT / p).resolve()


def ensure_dirs(cfg: dict[str, Any]) -> None:
    for key in ("data_root", "exports_dir", "raw_dir", "parsed_dir"):
        if key in cfg:
            resolve_path(cfg[key]).mkdir(parents=True, exist_ok=True)
    resolve_path(cfg.get("db_path", "data/db/pipeline.sqlite3")).parent.mkdir(
        parents=True, exist_ok=True
    )