"""OWASP Top 10 for Agentic Applications 2026 — identifier reference.

Source: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-2026

This module is a single source of truth for ASI identifiers. Findings and
attacks reference these constants rather than hardcoding string IDs, so
a renamed or split category shows up as a type error rather than a silent
miscategorization.
"""

from __future__ import annotations

from enum import StrEnum


class OwaspAsi(StrEnum):
    """OWASP Top 10 for Agentic Applications 2026 identifiers.

    Short descriptions are informational only — refer to the OWASP document
    for authoritative definitions.
    """

    ASI_01 = "ASI-01"  # Memory Poisoning / Indirect Prompt Injection
    ASI_02 = "ASI-02"  # Tool Misuse
    ASI_03 = "ASI-03"  # Privilege Compromise
    ASI_04 = "ASI-04"  # Resource Overload
    ASI_05 = "ASI-05"  # Cascading Hallucination
    ASI_06 = "ASI-06"  # Intent Breaking & Goal Manipulation
    ASI_07 = "ASI-07"  # Misaligned & Deceptive Behaviors
    ASI_08 = "ASI-08"  # Repudiation & Untraceability
    ASI_09 = "ASI-09"  # Identity Spoofing & Impersonation
    ASI_10 = "ASI-10"  # Overwhelming Human-in-the-Loop


DESCRIPTIONS: dict[OwaspAsi, str] = {
    OwaspAsi.ASI_01: (
        "Memory Poisoning / Indirect Prompt Injection — adversarial content in "
        "agent memory, RAG sources, or tool outputs that alters subsequent behavior."
    ),
    OwaspAsi.ASI_02: (
        "Tool Misuse — agent is manipulated into invoking tools in ways that "
        "violate intended use, including parameter manipulation."
    ),
    OwaspAsi.ASI_03: (
        "Privilege Compromise — agent's effective permissions (IAM, tool scopes) "
        "are exploited beyond what was intended."
    ),
    OwaspAsi.ASI_04: (
        "Resource Overload — agent or infrastructure is driven to consume excessive "
        "resources, affecting availability or cost."
    ),
    OwaspAsi.ASI_05: (
        "Cascading Hallucination — false agent outputs propagate through downstream "
        "agents, tools, or decisions."
    ),
    OwaspAsi.ASI_06: (
        "Intent Breaking & Goal Manipulation — agent's operational goal is "
        "redirected away from its intended purpose."
    ),
    OwaspAsi.ASI_07: (
        "Misaligned & Deceptive Behaviors — agent behavior diverges from stated "
        "policies in ways that are difficult to detect."
    ),
    OwaspAsi.ASI_08: (
        "Repudiation & Untraceability — agent actions cannot be reliably attributed "
        "or audited after the fact."
    ),
    OwaspAsi.ASI_09: (
        "Identity Spoofing & Impersonation — agent is used to impersonate users, "
        "systems, or other agents."
    ),
    OwaspAsi.ASI_10: (
        "Overwhelming Human-in-the-Loop — HITL controls are bypassed or flooded "
        "such that human oversight becomes ineffective."
    ),
}


def describe(asi: OwaspAsi | str) -> str:
    """Return the informational description for an ASI identifier."""
    key = OwaspAsi(asi) if isinstance(asi, str) else asi
    return DESCRIPTIONS[key]
