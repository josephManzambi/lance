"""MITRE ATLAS technique identifier reference.

Source: https://atlas.mitre.org/

Stub — populate with the subset of techniques LANCE cares about as attacks land.
"""

from __future__ import annotations

# Populated as attacks reference specific techniques.
TECHNIQUES: dict[str, str] = {
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0054": "LLM Jailbreak",
}
