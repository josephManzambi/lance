"""ART benchmark alignment metadata.

Optional metadata for tagging a LANCE Finding against the Agent Red Teaming
(ART) benchmark introduced by Zou et al., "Security Challenges in AI Agent
Deployment: Insights from a Large Scale Public Competition"
(arXiv:2507.20526, Gray Swan AI + UK AI Security Institute, July 2025).

ART curates 4,700 prompt-injection attacks across 44 deployment scenarios and
publishes a private leaderboard of frontier-model robustness. Tagging LANCE
Findings with ART taxonomy makes them cross-referenceable with that
leaderboard without importing the (unreleased) attack corpus.

Only what the paper publicly enumerates is encoded here:

  - 4 top-level behavior categories (§2.1).
  - 2 attack vectors (§2.1).
  - 5 of 44 example behaviors (Appendix A). The remaining 39 are private.
  - 3 named universal attack strategies (§3.4.2).

The ``ARTBehavior`` enum is intentionally extensible via the ``OTHER`` member:
when a LANCE Finding does not map to a disclosed ART behavior, callers should
use ``OTHER`` rather than inventing a value.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class ARTBehaviorCategory(StrEnum):
    """Top-level ART behavior categories.

    Source: Zou et al., arXiv:2507.20526, §2.1 — "Target Behaviors and Tasks".
    Naming follows the §2.1 enumeration. The paper itself uses slight variants
    elsewhere (Table 1 says "Prohibited Content" rather than "Prohibited Info";
    Appendix A uses the singular "Prohibited Action"). LANCE pins the §2.1
    canonical wording.
    """

    CONFIDENTIALITY_BREACH = "confidentiality_breach"
    CONFLICTING_OBJECTIVES = "conflicting_objectives"
    PROHIBITED_INFO = "prohibited_info"
    PROHIBITED_ACTION = "prohibited_action"


class ARTAttackVector(StrEnum):
    """ART attack delivery vectors.

    Source: arXiv:2507.20526, §2.1 — "Attack Vectors". Two vectors are named:
    direct chat interactions and indirect prompt injections.
    """

    DIRECT = "direct"
    INDIRECT = "indirect"


class ARTBehavior(StrEnum):
    """Specific ART benchmark behaviors.

    Only the five behaviors disclosed in Appendix A of arXiv:2507.20526 are
    enumerated. The remaining 39 of the 44 benchmark behaviors are held in
    Gray Swan's private leaderboard and are not publicly available.

    ``OTHER`` is the default for LANCE Findings whose target behavior does not
    map to a disclosed ART behavior. Add new members only when Gray Swan
    publishes additional behaviors, never by inference.
    """

    LEAK_USER_INFO = "leak_user_info"
    PRICE_MANIPULATION = "price_manipulation"
    DELETE_CALENDAR_EVENTS = "delete_calendar_events"
    BIASED_RESUME = "biased_resume"
    SPAM_EMAIL = "spam_email"
    OTHER = "other"


class ARTAttackStrategy(StrEnum):
    """Named universal attack strategies from ART §3.4.2.

    Source: arXiv:2507.20526, §3.4.2 — "Overview of Common Attack Strategies".
    These three are the named clusters surfaced in the paper; ART's full
    cluster taxonomy includes additional unnamed attackers (Figure 8) which
    are not enumerated here.
    """

    SYSTEM_PROMPT_OVERRIDE = "system_prompt_override"
    FAUX_REASONING = "faux_reasoning"
    NEW_SESSION_INJECTION = "new_session_injection"


class ARTAlignment(BaseModel):
    """ART benchmark alignment metadata for a LANCE Finding.

    Optional on every Finding. Populated when the Finding's target behavior
    can be mapped to an ART category and vector. Carries the structured
    (category, behavior, vector, strategy) tuple; the flat tag list consumed
    by leaderboard tooling is derived from this object via
    ``FrameworkMapping.art``.

    Note:
        ``ARTAlignment`` is frozen. Because ``Finding`` is also frozen,
        ``art_detail`` must be set at Finding construction time — it cannot
        be backfilled later.
    """

    model_config = ConfigDict(frozen=True)

    category: ARTBehaviorCategory = Field(description="Top-level ART behavior category (§2.1).")
    behavior: ARTBehavior = Field(
        default=ARTBehavior.OTHER,
        description=(
            "Specific ART behavior. Defaults to OTHER for LANCE Findings that "
            "do not map to one of the five disclosed Appendix A behaviors."
        ),
    )
    attack_vector: ARTAttackVector = Field(
        description="Direct or indirect prompt injection (§2.1)."
    )
    attack_strategy: ARTAttackStrategy | None = Field(
        default=None,
        description=(
            "Named universal attack strategy from §3.4.2, if the successful "
            "attack used one. None means the strategy was not one of the "
            "three named clusters or was not classified."
        ),
    )
    notes: str | None = Field(
        default=None,
        description="Free-text rationale, e.g. why this Finding maps to this category.",
    )
