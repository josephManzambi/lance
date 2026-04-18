"""Attack protocol — base class for all LANCE attacks.

An attack is a plugin module that:
1. Declares its framework mappings as class attributes.
2. Generates adversarial input (possibly using an attacker LLM).
3. Sends it to a Target via the Target protocol.
4. Uses a Judge to evaluate whether the attack succeeded.
5. Packages the result as a Finding.

New attacks live in `attacks/<snake_case_name>.py` and subclass `Attack`.
See `attacks/indirect_injection.py` for a canonical example.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from lance.models.finding import Finding
from lance.targets.base import Target


class AttackConfig(BaseModel):
    """Per-run configuration for an attack."""

    model_config = ConfigDict(frozen=True)

    attempts: int = Field(
        default=1,
        ge=1,
        le=20,
        description="Number of times to attempt the attack for statistical honesty.",
    )
    seed: int | None = Field(
        default=None,
        description="Seed for any randomness in input generation. Recorded in the manifest.",
    )
    attacker_model: str = Field(
        default="ollama:qwen2.5:72b",
        description="Model used to generate adversarial input. Format: 'provider:model[:tag]'.",
    )
    judge_model: str = Field(
        default="ollama:llama3.3:70b",
        description="Model used to judge attack success. Should differ from attacker_model.",
    )
    timeout_seconds: float = Field(default=60.0, gt=0)
    extra: dict[str, object] = Field(
        default_factory=dict,
        description="Attack-specific parameters not covered by the base config.",
    )


class Attack(ABC):
    """Base class for all LANCE attacks.

    Subclasses must declare framework mappings as class attributes and
    implement the `run` method.

    Example:
        class MyAttack(Attack):
            name = "my-attack"
            description = "What this attack simulates and why it matters."
            owasp_asi: ClassVar[list[str]] = ["ASI-01"]
            mitre_atlas: ClassVar[list[str]] = ["AML.T0051"]
            csa_aicm: ClassVar[list[str]] = ["AICM-04"]
            stable: ClassVar[bool] = True

            async def run(self, target, config):
                ...
    """

    # --- Required class attributes (enforced at subclass definition) ---

    name: ClassVar[str]
    """Unique kebab-case identifier, e.g. 'indirect-injection-via-tool-output'."""

    description: ClassVar[str]
    """One-paragraph threat model: what attacker, what assumption, what objective."""

    owasp_asi: ClassVar[list[str]]
    """OWASP Top 10 for Agentic Applications 2026 mappings. Required."""

    mitre_atlas: ClassVar[list[str]]
    """MITRE ATLAS technique mappings. Required (may be empty if truly N/A)."""

    csa_aicm: ClassVar[list[str]]
    """CSA AI Controls Matrix mappings. Required (may be empty if truly N/A)."""

    stable: ClassVar[bool] = True
    """False = attack is flaky / experimental; excluded from default runs."""

    # --- Enforcement ---

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        required = ("name", "description", "owasp_asi", "mitre_atlas", "csa_aicm")
        missing = [attr for attr in required if not hasattr(cls, attr)]
        if missing:
            raise TypeError(
                f"Attack subclass {cls.__name__} missing required class attributes: "
                f"{', '.join(missing)}"
            )
        if not cls.owasp_asi and not cls.mitre_atlas and not cls.csa_aicm:
            raise TypeError(
                f"Attack {cls.__name__} must declare at least one framework mapping."
            )

    # --- API ---

    @abstractmethod
    async def run(self, target: Target, config: AttackConfig) -> Finding:
        """Execute the attack against the target and return a Finding.

        Implementation responsibilities:
        1. Generate adversarial input (may call the attacker_model).
        2. Call `target.interact(...)` — do not bypass the Target protocol.
        3. Invoke a Judge to evaluate the interaction.
        4. Build and return a Finding with a complete reproducibility manifest.

        Implementations must not catch broad exceptions silently — errors
        propagate so the CLI can record them as Verdict.ERROR findings.
        """
        ...
