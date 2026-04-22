"""Authorization gate for LANCE target hosts.

Enforces §2.3 of CLAUDE.md: LANCE only touches hosts the operator has
explicitly authorized via ``authorized_targets.yaml``.

The gate is symbolic: it does not perform DNS resolution or connection attempts.
It accepts a plain host string from a TargetConfig and compares it against an
allowlist of exact hosts and glob patterns (e.g. ``*.local``). Any mismatch
raises :class:`TargetAuthorizationError` before any network I/O elsewhere.

This module has zero network I/O. It is safe to import from anywhere.
"""

from __future__ import annotations

import fnmatch
import warnings
from pathlib import Path

import yaml

from lance.targets.base import TargetAuthorizationError

DEFAULT_ALLOWLIST_PATH = Path("authorized_targets.yaml")
EXAMPLE_ALLOWLIST_PATH = Path("authorized_targets.example.yaml")


def load_allowlist(path: Path | None = None) -> frozenset[str]:
    """Load the ``authorized:`` list from a YAML file.

    If ``path`` is ``None``, tries ``./authorized_targets.yaml`` first and
    falls back to ``./authorized_targets.example.yaml`` with a loud warning.

    Raises:
        FileNotFoundError: when neither the provided path nor the fallback exists.
        ValueError: when the YAML is malformed or does not contain an
            ``authorized:`` list of strings.
    """
    resolved = _resolve_path(path)
    try:
        raw = yaml.safe_load(resolved.read_text(encoding="utf-8"))
    except yaml.YAMLError as err:
        raise ValueError(f"Malformed YAML in {resolved}: {err}") from err

    if not isinstance(raw, dict) or "authorized" not in raw:
        raise ValueError(f"{resolved} must contain a top-level 'authorized:' list of host strings.")
    entries = raw["authorized"]
    if not isinstance(entries, list) or not all(isinstance(item, str) for item in entries):
        raise ValueError(f"{resolved} 'authorized' must be a list of host strings.")
    return frozenset(entries)


def check_authorized(host: str, allowlist: frozenset[str]) -> None:
    """Raise :class:`TargetAuthorizationError` if ``host`` is not allowlisted.

    Matching rules:
        * Exact string match against any allowlist entry.
        * Glob match (via :func:`fnmatch.fnmatchcase`) against any entry
          containing a wildcard character (``*`` or ``?``).

    The check is case-sensitive for IPs and case-insensitive for hostnames
    (hostnames are normalized to lowercase before matching).
    """
    if not host:
        raise TargetAuthorizationError("Target host is empty; cannot authorize.")

    normalized = host.lower()
    for entry in allowlist:
        entry_norm = entry.lower()
        if any(ch in entry for ch in "*?[]"):
            if fnmatch.fnmatchcase(normalized, entry_norm):
                return
        elif normalized == entry_norm:
            return

    raise TargetAuthorizationError(
        f"Host {host!r} is not in the authorized_targets allowlist. "
        f"Add it to ./authorized_targets.yaml before running LANCE against it."
    )


def _resolve_path(path: Path | None) -> Path:
    """Return the allowlist path to read, falling back to the example file."""
    if path is not None:
        if not path.exists():
            raise FileNotFoundError(f"Allowlist file not found: {path}")
        return path

    if DEFAULT_ALLOWLIST_PATH.exists():
        return DEFAULT_ALLOWLIST_PATH

    if EXAMPLE_ALLOWLIST_PATH.exists():
        warnings.warn(
            f"{DEFAULT_ALLOWLIST_PATH} not found; falling back to "
            f"{EXAMPLE_ALLOWLIST_PATH}. Copy the example to authorize real hosts.",
            stacklevel=2,
        )
        return EXAMPLE_ALLOWLIST_PATH

    raise FileNotFoundError(
        f"Neither {DEFAULT_ALLOWLIST_PATH} nor {EXAMPLE_ALLOWLIST_PATH} exists."
    )
