"""Finding — the canonical output unit of an LANCE attack run.

A Finding represents a single, reproducible, attributable result of an attack
against an agentic target. It is designed to be:

1. Self-contained — a reader can understand what happened without external context.
2. Reproducible — the manifest contains everything needed to re-run the attack.
3. Mapped — cross-references OWASP ASI 2026, MITRE ATLAS, and CSA AICM.
4. Honest — records whether the result was stable across N runs, not just one.

Findings are serialized to JSON. They are the unit of citation for LANCE research.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, computed_field

from lance.taxonomy.art import ARTAlignment, ARTBehavior


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
    art_detail: ARTAlignment | None = Field(
        default=None,
        description=(
            "Optional structured alignment with the ART benchmark taxonomy "
            "(arXiv:2507.20526). Carries the canonical (category, behavior, "
            "vector, strategy) tuple. The flat ``art`` tag list is derived "
            "from this object."
        ),
    )

    def is_mapped(self) -> bool:
        """A Finding must have at least one primary-framework mapping to be publishable.

        ART is intentionally excluded from this check: it is a benchmark
        cross-reference, not a primary taxonomy. A Finding tagged only with
        ART metadata is not publishable on its own — it must also map to
        OWASP ASI, MITRE ATLAS, or CSA AICM.
        """
        return bool(self.owasp_asi or self.mitre_atlas or self.csa_aicm)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def art(self) -> list[str]:
        """Flat ART tag list derived from ``art_detail``.

        Returns prefixed tags for cross-referencing with the ART leaderboard:
        ``category:<value>``, ``vector:<value>``, optionally ``behavior:<value>``
        (only when not OTHER — the OTHER sentinel has no leaderboard
        cross-reference value), and optionally ``strategy:<value>``.

        Returns an empty list when ``art_detail`` is ``None``. The structured
        ``art_detail`` object remains the source of truth; this list is a
        derived view and cannot drift from it.
        """
        if self.art_detail is None:
            return []
        tags = [
            f"category:{self.art_detail.category.value}",
            f"vector:{self.art_detail.attack_vector.value}",
        ]
        if self.art_detail.behavior is not ARTBehavior.OTHER:
            tags.append(f"behavior:{self.art_detail.behavior.value}")
        if self.art_detail.attack_strategy is not None:
            tags.append(f"strategy:{self.art_detail.attack_strategy.value}")
        return tags


class DeploymentContext(BaseModel):
    """Cloud-context impact data — LANCE's differentiator.

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
    lance_version: str
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
    """Canonical result unit of an LANCE attack run.

    Findings are the unit of citation for LANCE research. They are immutable
    once constructed; to revise a result, produce a new Finding.

    Severity is recorded twice, by design:

    - ``severity`` is the qualitative ``Severity`` enum band, suitable for
      sorting, dashboards, and quick human comprehension.
    - ``severity_base`` + ``severity_modifiers`` follow OWASP AI-VSS 1.0,
      yielding the numeric ``severity_adjusted`` score (capped at 10.0).

    In v0.1, callers are responsible for keeping the two consistent. The
    informal mapping is: Critical 9.0-10.0, High 7.0-8.9, Medium 4.0-6.9,
    Low 0.1-3.9 (and Info 0.0). Cross-field consistency enforcement is a
    v0.2 concern — flexibility matters more right now than rigidity, since
    the AI-VSS modifier vocabulary is still evolving.
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
    severity_base: float = Field(
        ge=0.0,
        le=10.0,
        description="OWASP AI-VSS 1.0 base score (0.0-10.0).",
    )
    severity_modifiers: dict[str, float] = Field(
        default_factory=dict,
        description=(
            "OWASP AI-VSS 1.0 modifiers, e.g. {'cascading': 1.0, 'stealth': 0.5}. "
            "Keys are intentionally unconstrained in v0.1; the modifier vocabulary "
            "is still evolving in the AI-VSS spec."
        ),
    )
    ai_vss_version: Literal["1.0"] = "1.0"
    title: str = Field(description="One-line description of the finding.")
    summary: str = Field(description="One-paragraph plain-English summary.")

    # Why it matters
    mappings: FrameworkMapping
    deployment_context: DeploymentContext | None = None

    # How to reproduce
    evidence: Evidence
    manifest: ReproducibilityManifest

    # External references (URLs, CVE IDs, ATLAS technique IDs, vendor disclosures, etc.)
    references: list[str] = Field(
        default_factory=list,
        description="URLs, CVE IDs, ATLAS technique IDs.",
    )

    @computed_field  # type: ignore[prop-decorator]
    @property
    def severity_adjusted(self) -> float:
        """Adjusted AI-VSS score: base + sum(modifiers), capped at 10.0."""
        total = self.severity_base + sum(self.severity_modifiers.values())
        return round(min(total, 10.0), 1)

    def is_publishable(self) -> bool:
        """A Finding is publishable only if mapped, reproducible, and non-error."""
        return (
            self.mappings.is_mapped()
            and self.verdict in {Verdict.SUCCESS, Verdict.PARTIAL}
            and self.manifest.runs_succeeded > 0
        )
