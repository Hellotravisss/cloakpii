"""Helpers for optional runtime dependencies.

Parquet (pyarrow) and Excel (openpyxl) support are optional extras so the base
install stays light. Format handlers import their backend via ``require()``,
which raises a clear, actionable error if the extra is not installed.
"""

from __future__ import annotations

import importlib


def require(module_name: str, extra: str):
    """Import ``module_name`` or raise a helpful error naming the missing extra."""
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:  # pragma: no cover - exercised via the handlers
        raise ImportError(
            f"This feature needs the optional '{extra}' dependency. "
            f"Install it with:  pip install \"cloakpii[{extra}]\""
        ) from exc
