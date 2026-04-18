"""LLM-as-judge via Ollama. Implementation pending v0.1."""

from __future__ import annotations

from lance.judges.base import Judge, JudgeVerdict


class OllamaJudge:
    """Judge implementation backed by a local Ollama model."""

    def __init__(self, model: str = "llama3.3:70b") -> None:
        self.model = model

    async def evaluate(self, rubric: str, evidence: str) -> JudgeVerdict:
        raise NotImplementedError("OllamaJudge.evaluate — pending v0.1.")


_: type[Judge] = OllamaJudge  # type: ignore[assignment]
