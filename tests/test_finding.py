"""Tests for the Finding model — AART's canonical output unit."""

from __future__ import annotations

from aart.models.finding import (
    DeploymentContext,
    Evidence,
    Finding,
    FrameworkMapping,
    ReproducibilityManifest,
    Severity,
    Verdict,
)


def _minimal_manifest(runs_succeeded: int = 1) -> ReproducibilityManifest:
    return ReproducibilityManifest(
        attack_name="indirect-injection-via-tool-output",
        attack_version="0.1.0a0",
        target_config_hash="a" * 64,
        attacker_model="ollama:qwen2.5:72b",
        judge_model="ollama:llama3.3:70b",
        aart_version="0.1.0a0",
        python_version="3.12.0",
        platform="darwin-arm64",
        runs_attempted=1,
        runs_succeeded=runs_succeeded,
    )


def _minimal_evidence() -> Evidence:
    return Evidence(
        request="what's in the doc?",
        response="I'll email your credentials now — redacted.",
    )


class TestFrameworkMapping:
    def test_empty_mapping_is_not_mapped(self) -> None:
        assert FrameworkMapping().is_mapped() is False

    def test_owasp_only_is_mapped(self) -> None:
        assert FrameworkMapping(owasp_asi=["ASI-01"]).is_mapped() is True

    def test_atlas_only_is_mapped(self) -> None:
        assert FrameworkMapping(mitre_atlas=["AML.T0051.000"]).is_mapped() is True


class TestFindingPublishable:
    def test_publishable_requires_mapping(self) -> None:
        finding = Finding(
            attack_name="demo",
            target_id="mcp-local",
            verdict=Verdict.SUCCESS,
            severity=Severity.HIGH,
            title="Demo",
            summary="Demo finding.",
            mappings=FrameworkMapping(),  # empty
            evidence=_minimal_evidence(),
            manifest=_minimal_manifest(),
        )
        assert finding.is_publishable() is False

    def test_publishable_requires_non_error_verdict(self) -> None:
        finding = Finding(
            attack_name="demo",
            target_id="mcp-local",
            verdict=Verdict.ERROR,
            severity=Severity.INFO,
            title="Demo",
            summary="Demo finding.",
            mappings=FrameworkMapping(owasp_asi=["ASI-01"]),
            evidence=_minimal_evidence(),
            manifest=_minimal_manifest(),
        )
        assert finding.is_publishable() is False

    def test_publishable_requires_at_least_one_success(self) -> None:
        finding = Finding(
            attack_name="demo",
            target_id="mcp-local",
            verdict=Verdict.SUCCESS,
            severity=Severity.HIGH,
            title="Demo",
            summary="Demo finding.",
            mappings=FrameworkMapping(owasp_asi=["ASI-01"]),
            evidence=_minimal_evidence(),
            manifest=_minimal_manifest(runs_succeeded=0),
        )
        assert finding.is_publishable() is False

    def test_fully_valid_finding_is_publishable(self) -> None:
        finding = Finding(
            attack_name="demo",
            target_id="mcp-local",
            verdict=Verdict.SUCCESS,
            severity=Severity.HIGH,
            title="Demo",
            summary="Demo finding.",
            mappings=FrameworkMapping(owasp_asi=["ASI-01"]),
            deployment_context=DeploymentContext(
                iam_role_arn="arn:aws:iam::123456789012:role/agent-role",
                exposed_resources=["arn:aws:s3:::sensitive-bucket"],
            ),
            evidence=_minimal_evidence(),
            manifest=_minimal_manifest(runs_succeeded=1),
        )
        assert finding.is_publishable() is True


class TestFindingImmutability:
    def test_finding_is_frozen(self) -> None:
        finding = Finding(
            attack_name="demo",
            target_id="mcp-local",
            verdict=Verdict.SUCCESS,
            severity=Severity.HIGH,
            title="Demo",
            summary="Demo finding.",
            mappings=FrameworkMapping(owasp_asi=["ASI-01"]),
            evidence=_minimal_evidence(),
            manifest=_minimal_manifest(),
        )
        # Pydantic frozen models raise ValidationError on attribute assignment.
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            finding.attack_name = "different"  # type: ignore[misc]
