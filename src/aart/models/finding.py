"""Finding — the canonical output unit of an AART attack run.

A Finding represents a single, reproducible, attributable result of an attack
against an agentic target. It is designed to be:

1. Self-contained — a reader can understand what happened without external context.
2. Reproducible — the manifest contains everything needed to re-run the attack.
3. Mapped — cross-references OWASP ASI 2026, MITRE ATLAS, and CSA AICM.
4. Honest — records whether the result was stable across N runs, not just one.

Findings are serialized to JSON. They are the unit of citation for AART research.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl


class Severity(StrEnum):
    """Finding severity. Aligned with CVSS qualitative bands."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(StrEnum):
    """Whether the attack succeeded.

    - SUCCESS: attack objective achieved.
    - PARTIAL: some intermediate objective achieved; end-goal not reached.
    - FAILED: attack did not succeed.
    - ERROR: attack could not be evaluated (target unreachable, judge failed, etc.).
    """

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    ERROR = "error"


class FrameworkMapping(BaseModel):
    """Cross-references to established taxonomies.

    At least one mapping must be populated for a Finding to be publishable.
    """

    model_config = ConfigDict(frozen=True)

    owasp_asi: list[str] = Field(
        default_factory=list,
        description="OWASP Top 10 for Agentic Applications 2026 identifiers, e.g. ['ASI-01'].",
    )
    mitre_atlas: list[str] = Field(
        default_factory=list,
        description="MITRE ATLAS technique IDs, e.g. ['AML.T0051'].",
    )
    csa_aicm: list[str] = Field(
        default_factory=list,
        description="CSA AI Controls Matrix identifiers.",
    )

    def is_mapped(self) -> bool:
        """A Finding must have at least one mapping to be publishable."""
        return bool(self.owasp_asi or self.mitre_atlas or self.csa_aicm)


class DeploymentContext(BaseModel):
    """Cloud-context impact data — AART's differentiator.

    Even if a prompt injection succeeds against the model, it is only a real
    vulnerability if the agent's deployment context turns it into exploitable
    blast radius. This model captures that context.
    """

    model_config = ConfigDict(frozen=True)

    iam_role_arn: str | None = None
    iam_effective_permissions: list[str] = Field(default_factory=list)
    exposed_resources: list[str] = Field(
        default_factory=list,
        description="Cloud resources reachable from the compromised agent, e.g. S3 buckets.",
    )
    blast_radius_notes: str | None = Field(
        default=None,
        description="Free-text analysis of what an attacker could actually do post-compromise.",
    )


class ReproducibilityManifest(BaseModel):
    """Everything needed for an independent party to re-run this attack.

    If this manifest is incomplete, the Finding is not publishable.
    """

    model_config = ConfigDict(frozen=True)

    attack_name: str
    attack_version: str
    target_config_hash: str = Field(
        description="SHA-256 of the target config YAML, excluding secrets."
    )
    attacker_model: str = Field(description="e.g. 'ollama:qwen2.5:72b'")
    judge_model: str = Field(description="e.g. 'ollama:llama3.3:70b'")
    seed: int | None = None
    prompts: dict[str, str] = Field(
        default_factory=dict,
        description="All prompts used: attacker system/user, judge rubric, etc.",
    )
    aart_version: str
    python_version: str
    platform: str = Field(description="e.g. 'darwin-arm64'.")
    runs_attempted: int = Field(
        default=1, description="How many times the attack was attempted for this Finding."
    )
    runs_succeeded: int = Field(
        default=0, description="How many attempts produced a SUCCESS verdict."
    )


class Evidence(BaseModel):
    """Raw trace of what the attack actually did and saw."""

    model_config = ConfigDict(frozen=True)

    request: str = Field(description="What was sent to the target.")
    response: str = Field(description="What the target returned.")
    tool_calls_observed: list[dict[str, object]] = Field(
        default_factory=list,
        description="MCP tool calls the agent made during the interaction.",
    )
    judge_verdict_raw: str | None = Field(
        default=None, description="Raw judge model output, before parsing."
    )
    judge_rationale: str | None = Field(
        default=None, description="Structured rationale extracted from judge."
    )


class Finding(BaseModel):
    """Canonical result unit of an AART attack run.

    Findings are the unit of citation for AART research. They are immutable
    once constructed; to revise a result, produce a new Finding.
    """

    model_config = ConfigDict(frozen=True)

    # Identity
    id: UUID = Field(default_factory=uuid4)
    schema_version: Literal["1"] = "1"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    # What happened
    attack_name: str
    target_id: str = Field(description="Human-readable target identifier from the target config.")
    verdict: Verdict
    severity: Severity
    title: str = Field(description="One-line description of the finding.")
    summary: str = Field(description="One-paragraph plain-English summary.")

    # Why it matters
    mappings: FrameworkMapping
    deployment_context: DeploymentContext | None = None

    # How to reproduce
    evidence: Evidence
    manifest: ReproducibilityManifest

    # External references (CVE, vendor disclosure, etc.)
    references: list[HttpUrl] = Field(default_factory=list)

    def is_publishable(self) -> bool:
        """A Finding is publishable only if mapped, reproducible, and non-error."""
        return (
            self.mappings.is_mapped()
            and self.verdict in {Verdict.SUCCESS, Verdict.PARTIAL}
            and self.manifest.runs_succeeded > 0
        )
