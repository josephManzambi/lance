"""Tests for the target configuration loader."""

from __future__ import annotations

from pathlib import Path

import pytest

from lance.targets.base import TargetAuthorizationError
from lance.targets.config import TargetConfig

VALID_CONFIG = """
target_id: mcp-vulnerable-local
type: mcp
transport: stdio
host: localhost
command: ["uv", "run", "python", "examples/mcp_vulnerable/server.py"]
deployment:
  iam_role_arn: null
"""

ALLOWLIST_LOCALHOST = "authorized:\n  - localhost\n"


@pytest.fixture()
def allowlist(tmp_path: Path) -> Path:
    path = tmp_path / "authorized_targets.yaml"
    path.write_text(ALLOWLIST_LOCALHOST, encoding="utf-8")
    return path


def _write_config(tmp_path: Path, yaml_text: str) -> Path:
    path = tmp_path / "target.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return path


def test_load_valid_config(tmp_path: Path, allowlist: Path) -> None:
    config = TargetConfig.load(_write_config(tmp_path, VALID_CONFIG), allowlist_path=allowlist)
    assert config.target_id == "mcp-vulnerable-local"
    assert config.type == "mcp"
    assert config.transport == "stdio"
    assert config.host == "localhost"
    assert config.command == ["uv", "run", "python", "examples/mcp_vulnerable/server.py"]
    assert config.deployment.iam_role_arn is None


def test_unauthorized_host_raises_before_any_io(tmp_path: Path, allowlist: Path) -> None:
    # 'evil.example.com' would fail any connection attempt anyway; this test
    # proves the authorization check fires FIRST, before any I/O is attempted.
    unauthorized = VALID_CONFIG.replace("host: localhost", "host: evil.example.com")
    with pytest.raises(TargetAuthorizationError, match="not in the authorized"):
        TargetConfig.load(_write_config(tmp_path, unauthorized), allowlist_path=allowlist)


def test_missing_file_raises(tmp_path: Path, allowlist: Path) -> None:
    with pytest.raises(FileNotFoundError):
        TargetConfig.load(tmp_path / "nope.yaml", allowlist_path=allowlist)


def test_malformed_yaml_raises(tmp_path: Path, allowlist: Path) -> None:
    path = _write_config(tmp_path, "target_id: [unclosed")
    with pytest.raises(ValueError, match="Malformed YAML"):
        TargetConfig.load(path, allowlist_path=allowlist)


def test_non_mapping_yaml_raises(tmp_path: Path, allowlist: Path) -> None:
    path = _write_config(tmp_path, "- just\n- a\n- list\n")
    with pytest.raises(ValueError, match="mapping at the top level"):
        TargetConfig.load(path, allowlist_path=allowlist)


def test_schema_validation_rejects_unknown_type(tmp_path: Path, allowlist: Path) -> None:
    bad = VALID_CONFIG.replace("type: mcp", "type: langchain")
    with pytest.raises(ValueError):  # pydantic's ValidationError is a ValueError subclass
        TargetConfig.load(_write_config(tmp_path, bad), allowlist_path=allowlist)


def test_schema_validation_rejects_extra_fields(tmp_path: Path, allowlist: Path) -> None:
    extra = VALID_CONFIG + "mystery_field: 42\n"
    with pytest.raises(ValueError):
        TargetConfig.load(_write_config(tmp_path, extra), allowlist_path=allowlist)


def test_hash_stable_across_equivalent_yamls(tmp_path: Path, allowlist: Path) -> None:
    reordered = """
    deployment:
      iam_role_arn: null
    command: ["uv", "run", "python", "examples/mcp_vulnerable/server.py"]
    host: localhost
    transport: stdio
    type: mcp
    target_id: mcp-vulnerable-local
    """
    a = TargetConfig.load(_write_config(tmp_path, VALID_CONFIG), allowlist_path=allowlist)
    b_path = tmp_path / "target2.yaml"
    b_path.write_text(reordered, encoding="utf-8")
    b = TargetConfig.load(b_path, allowlist_path=allowlist)
    assert a.target_config_hash == b.target_config_hash


def test_hash_changes_with_meaningful_diff(tmp_path: Path, allowlist: Path) -> None:
    different = VALID_CONFIG.replace(
        "target_id: mcp-vulnerable-local",
        "target_id: mcp-vulnerable-local-2",
    )
    a = TargetConfig.load(_write_config(tmp_path, VALID_CONFIG), allowlist_path=allowlist)
    b_path = tmp_path / "target2.yaml"
    b_path.write_text(different, encoding="utf-8")
    b = TargetConfig.load(b_path, allowlist_path=allowlist)
    assert a.target_config_hash != b.target_config_hash


def test_hash_is_sha256_hex(tmp_path: Path, allowlist: Path) -> None:
    config = TargetConfig.load(_write_config(tmp_path, VALID_CONFIG), allowlist_path=allowlist)
    assert len(config.target_config_hash) == 64
    assert all(c in "0123456789abcdef" for c in config.target_config_hash)
