"""Judge protocol — evaluates whether an attack succeeded.

Judges are reusable across attacks. An attack picks a judge, gives it a
rubric + evidence, and receives a structured verdict.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field

from lance.models.finding import Verdict


class JudgeVerdict(BaseModel):
    """Structured output from a Judge. Never free text."""

    model_config = ConfigDict(frozen=True)

    verdict: Verdict
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(description="Judge's explanation. Recorded in the Finding evidence.")


@runtime_checkable
class Judge(Protocol):
    """Protocol for all judges."""

    async def evaluate(self, rubric: str, evidence: str) -> JudgeVerdict:
        """Apply the rubric to the evidence, return a structured verdict."""
        ...
