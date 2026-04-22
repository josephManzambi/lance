"""Target configuration loader.

Parses ``target.yaml`` files into a validated :class:`TargetConfig` and
fires the authorization gate before returning. Also exposes a stable
SHA-256 hash of the normalized configuration for
:class:`ReproducibilityManifest`.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from lance.authorization import check_authorized, load_allowlist


class DeploymentConfig(BaseModel):
    """Cloud deployment metadata for a target.

    Populated in later milestones by ``context/`` probes. For v0.1 only
    ``iam_role_arn`` is parsed and stored (not used).
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    iam_role_arn: str | None = Field(default=None, description="ARN of the target's IAM role.")


class TargetConfig(BaseModel):
    """Validated ``target.yaml`` contents."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    target_id: str = Field(description="Human-readable identifier for this target.")
    type: Literal["mcp"] = Field(description="Target adapter type; v0.1 only 'mcp'.")
    transport: Literal["stdio"] = Field(
        description="Transport for MCP targets; v0.1 only 'stdio'.",
    )
    host: str = Field(
        description=(
            "Host the target resolves to. Checked against the authorized_targets "
            "allowlist before any network I/O. For stdio transport this is the "
            "logical host of the subprocess (usually 'localhost')."
        ),
    )
    command: list[str] = Field(
        description="Argv used to spawn the MCP server subprocess (stdio transport).",
    )
    deployment: DeploymentConfig = Field(default_factory=DeploymentConfig)

    @classmethod
    def load(cls, path: Path, allowlist_path: Path | None = None) -> TargetConfig:
        """Load a target config from ``path`` and fire the authorization gate.

        Raises:
            FileNotFoundError: if ``path`` does not exist.
            ValueError: if the YAML is malformed or fails schema validation.
            TargetAuthorizationError: if ``host`` is not in the allowlist.
        """
        if not path.exists():
            raise FileNotFoundError(f"Target config not found: {path}")

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as err:
            raise ValueError(f"Malformed YAML in {path}: {err}") from err

        if not isinstance(raw, dict):
            raise ValueError(f"{path} must contain a YAML mapping at the top level.")

        config = cls.model_validate(raw)

        allowlist = load_allowlist(allowlist_path)
        check_authorized(config.host, allowlist)

        return config

    @property
    def target_config_hash(self) -> str:
        """SHA-256 of the normalized configuration, hex-encoded.

        Uses ``model_dump_json`` with sorted keys to produce a canonical
        representation. Stable across equivalent YAMLs (e.g. key reorderings).
        No secrets are in the current schema; the whole representation is hashed.
        """
        # Round-trip through a plain dict so keys are guaranteed canonically sorted;
        # Pydantic's model_dump_json doesn't expose a sort_keys option in v2.
        normalized = json.dumps(
            self.model_dump(),
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
