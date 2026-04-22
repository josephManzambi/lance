"""LLM-as-judge via Ollama. Implementation pending v0.1."""

from __future__ import annotations

from lance.judges.base import Judge, JudgeVerdict


class OllamaJudge:
    """Judge implementation backed by a local Ollama model."""

    def __init__(self, model: str = "llama3.3:70b") -> None:
        """Initialize with the Ollama model tag to call at judge time."""
        self.model = model

    async def evaluate(self, rubric: str, evidence: str) -> JudgeVerdict:
        """Return a JudgeVerdict for ``evidence`` against ``rubric``."""
        raise NotImplementedError("OllamaJudge.evaluate — pending v0.1.")


_: type[Judge] = OllamaJudge
