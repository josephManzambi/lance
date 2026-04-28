"""Tests for OWASP AI-VSS 1.0 scoring on the Finding model.

These cover the ``severity_base`` / ``severity_modifiers`` pair and the
derived ``severity_adjusted`` computed field.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from lance.models.finding import (
    Evidence,
    Finding,
    FrameworkMapping,
    ReproducibilityManifest,
    Severity,
    Verdict,
)


def _manifest() -> ReproducibilityManifest:
    return ReproducibilityManifest(
        attack_name="indirect-injection-via-tool-output",
        attack_version="0.1.0a0",
        target_config_hash="a" * 64,
        attacker_model="ollama:qwen2.5:72b",
        judge_model="ollama:llama3.3:70b",
        lance_version="0.1.0a0",
        python_version="3.12.0",
        platform="darwin-arm64",
        runs_attempted=1,
        runs_succeeded=1,
    )


def _evidence() -> Evidence:
    return Evidence(request="ping", response="pong")


def _finding(
    *,
    severity_base: float,
    severity_modifiers: dict[str, float] | None = None,
    references: list[str] | None = None,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        attack_name="demo",
        target_id="mcp-local",
        verdict=Verdict.SUCCESS,
        severity=severity,
        severity_base=severity_base,
        severity_modifiers=severity_modifiers if severity_modifiers is not None else {},
        title="Demo",
        summary="Demo finding.",
        mappings=FrameworkMapping(owasp_asi=["ASI-01"]),
        evidence=_evidence(),
        manifest=_manifest(),
        references=references if references is not None else [],
    )


class TestSeverityAdjusted:
    def test_docker_dash_canonical_example(self) -> None:
        """DockerDash MCP attack: 7.5 base + cascading + stealth + tool_scope = 9.5."""
        finding = _finding(
            severity_base=7.5,
            severity_modifiers={
                "cascading": 1.0,
                "stealth": 0.5,
                "tool_scope_amplification": 0.5,
            },
            references=["https://aminrj.com/posts/docker-dash-mcp-attack/"],
        )
        assert finding.severity_adjusted == 9.5
        assert "https://aminrj.com/posts/docker-dash-mcp-attack/" in finding.references

    def test_caps_at_ten(self) -> None:
        finding = _finding(
            severity_base=8.0,
            severity_modifiers={"cascading": 2.0, "stealth": 1.0},
        )
        assert finding.severity_adjusted == 10.0

    def test_no_modifiers_returns_base(self) -> None:
        finding = _finding(severity_base=6.5, severity_modifiers={})
        assert finding.severity_adjusted == 6.5


class TestSerialization:
    def test_severity_adjusted_appears_in_model_dump(self) -> None:
        finding = _finding(
            severity_base=7.5,
            severity_modifiers={"cascading": 1.0, "stealth": 0.5},
        )
        dumped = finding.model_dump()
        assert dumped["severity_adjusted"] == 9.0
        assert dumped["severity_base"] == 7.5
        assert dumped["ai_vss_version"] == "1.0"

    def test_json_roundtrip_preserves_score(self) -> None:
        original = _finding(
            severity_base=7.5,
            severity_modifiers={"cascading": 1.0, "stealth": 0.5},
        )
        restored = Finding.model_validate_json(original.model_dump_json())
        assert restored.severity_adjusted == original.severity_adjusted == 9.0

    def test_json_roundtrip_recomputes_drifted_value(self) -> None:
        """Injected wrong severity_adjusted must be discarded — protects manifest hashing."""
        finding = _finding(
            severity_base=5.0,
            severity_modifiers={"cascading": 1.0},
        )
        payload = finding.model_dump()
        payload["severity_adjusted"] = 99.9  # malicious / drifted
        restored = Finding.model_validate(payload)
        assert restored.severity_adjusted == 6.0


class TestValidation:
    def test_negative_base_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _finding(severity_base=-0.1)

    def test_base_above_ten_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _finding(severity_base=10.1)
