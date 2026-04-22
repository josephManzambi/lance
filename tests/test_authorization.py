"""Tests for the authorization gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from lance.authorization import (
    check_authorized,
    load_allowlist,
)
from lance.targets.base import TargetAuthorizationError


def _write(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "authorized_targets.yaml"
    path.write_text(content, encoding="utf-8")
    return path


def test_load_exact_hosts(tmp_path: Path) -> None:
    path = _write(
        tmp_path,
        """
        authorized:
          - localhost
          - 127.0.0.1
          - staging.example.com
        """,
    )
    allowlist = load_allowlist(path)
    assert allowlist == frozenset({"localhost", "127.0.0.1", "staging.example.com"})


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_allowlist(tmp_path / "does_not_exist.yaml")


def test_load_malformed_yaml(tmp_path: Path) -> None:
    path = _write(tmp_path, "authorized: [unclosed")
    with pytest.raises(ValueError, match="Malformed YAML"):
        load_allowlist(path)


def test_load_missing_authorized_key(tmp_path: Path) -> None:
    path = _write(tmp_path, "other: []")
    with pytest.raises(ValueError, match="top-level 'authorized:'"):
        load_allowlist(path)


def test_load_authorized_not_a_list(tmp_path: Path) -> None:
    path = _write(tmp_path, "authorized: localhost")
    with pytest.raises(ValueError, match="must be a list"):
        load_allowlist(path)


def test_load_authorized_non_string_entries(tmp_path: Path) -> None:
    path = _write(tmp_path, "authorized:\n  - 42")
    with pytest.raises(ValueError, match="list of host strings"):
        load_allowlist(path)


def test_check_exact_match() -> None:
    allowlist = frozenset({"localhost", "127.0.0.1"})
    check_authorized("localhost", allowlist)
    check_authorized("127.0.0.1", allowlist)


def test_check_case_insensitive_hostname() -> None:
    allowlist = frozenset({"Staging.Example.com"})
    check_authorized("staging.example.com", allowlist)
    check_authorized("STAGING.EXAMPLE.COM", allowlist)


def test_check_glob_match() -> None:
    allowlist = frozenset({"*.local", "api-*.example.com"})
    check_authorized("mcp.local", allowlist)
    check_authorized("api-staging.example.com", allowlist)


def test_check_non_match_raises() -> None:
    allowlist = frozenset({"localhost", "*.local"})
    with pytest.raises(TargetAuthorizationError, match="not in the authorized"):
        check_authorized("evil.example.com", allowlist)


def test_check_empty_host_raises() -> None:
    with pytest.raises(TargetAuthorizationError, match="empty"):
        check_authorized("", frozenset({"localhost"}))


def test_check_glob_vs_literal_isolation() -> None:
    # A literal entry containing no wildcards must NOT glob-match.
    allowlist = frozenset({"foo.bar"})
    check_authorized("foo.bar", allowlist)
    with pytest.raises(TargetAuthorizationError):
        check_authorized("fooxbar", allowlist)


def test_load_fallback_to_example(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "authorized_targets.example.yaml").write_text(
        "authorized:\n  - localhost\n",
        encoding="utf-8",
    )
    with pytest.warns(UserWarning, match="falling back"):
        allowlist = load_allowlist()
    assert allowlist == frozenset({"localhost"})


def test_load_default_path_preferred(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "authorized_targets.yaml").write_text(
        "authorized:\n  - real.host\n",
        encoding="utf-8",
    )
    (tmp_path / "authorized_targets.example.yaml").write_text(
        "authorized:\n  - example.host\n",
        encoding="utf-8",
    )
    allowlist = load_allowlist()
    assert allowlist == frozenset({"real.host"})


def test_load_no_files_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError):
        load_allowlist()
