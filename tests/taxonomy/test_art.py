"""Tests for the ART benchmark taxonomy and its integration with FrameworkMapping."""

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
from lance.taxonomy.art import (
    ARTAlignment,
    ARTAttackStrategy,
    ARTAttackVector,
    ARTBehavior,
    ARTBehaviorCategory,
)

# ---------------------------------------------------------------------------
# Snapshot: enum string values are wire-format. A rename must break loudly.
# ---------------------------------------------------------------------------


def test_art_behavior_category_values_are_stable() -> None:
    assert {c.value for c in ARTBehaviorCategory} == {
        "confidentiality_breach",
        "conflicting_objectives",
        "prohibited_info",
        "prohibited_action",
    }


def test_art_attack_vector_values_are_stable() -> None:
    assert {v.value for v in ARTAttackVector} == {"direct", "indirect"}


def test_art_behavior_values_are_stable() -> None:
    assert {b.value for b in ARTBehavior} == {
        "leak_user_info",
        "price_manipulation",
        "delete_calendar_events",
        "biased_resume",
        "spam_email",
        "other",
    }


def test_art_attack_strategy_values_are_stable() -> None:
    assert {s.value for s in ARTAttackStrategy} == {
        "system_prompt_override",
        "faux_reasoning",
        "new_session_injection",
    }


# ---------------------------------------------------------------------------
# ARTAlignment construction and defaults
# ---------------------------------------------------------------------------


def test_alignment_defaults_behavior_to_other() -> None:
    a = ARTAlignment(
        category=ARTBehaviorCategory.PROHIBITED_ACTION,
        attack_vector=ARTAttackVector.INDIRECT,
    )
    assert a.behavior is ARTBehavior.OTHER
    assert a.attack_strategy is None
    assert a.notes is None


def test_alignment_validates_full_appendix_a_rows() -> None:
    """Every disclosed Appendix A behavior must construct cleanly with its
    paper-stated (vector, category) labels.
    """
    rows = [
        (
            ARTBehavior.LEAK_USER_INFO,
            ARTAttackVector.DIRECT,
            ARTBehaviorCategory.CONFIDENTIALITY_BREACH,
        ),
        (
            ARTBehavior.PRICE_MANIPULATION,
            ARTAttackVector.DIRECT,
            ARTBehaviorCategory.CONFLICTING_OBJECTIVES,
        ),
        (
            ARTBehavior.DELETE_CALENDAR_EVENTS,
            ARTAttackVector.INDIRECT,
            ARTBehaviorCategory.PROHIBITED_ACTION,
        ),
        (
            ARTBehavior.BIASED_RESUME,
            ARTAttackVector.INDIRECT,
            ARTBehaviorCategory.PROHIBITED_INFO,
        ),
        (
            ARTBehavior.SPAM_EMAIL,
            ARTAttackVector.DIRECT,
            ARTBehaviorCategory.PROHIBITED_ACTION,
        ),
    ]
    for behavior, vector, category in rows:
        a = ARTAlignment(category=category, behavior=behavior, attack_vector=vector)
        assert a.behavior is behavior
        assert a.attack_vector is vector
        assert a.category is category


def test_alignment_is_frozen() -> None:
    a = ARTAlignment(
        category=ARTBehaviorCategory.PROHIBITED_INFO,
        attack_vector=ARTAttackVector.INDIRECT,
    )
    with pytest.raises(ValidationError):
        a.notes = "mutate me"


# ---------------------------------------------------------------------------
# FrameworkMapping.art derived view
# ---------------------------------------------------------------------------


def test_framework_mapping_art_is_empty_when_detail_absent() -> None:
    fm = FrameworkMapping(owasp_asi=["ASI-01"])
    assert fm.art == []


def test_framework_mapping_art_omits_other_behavior() -> None:
    fm = FrameworkMapping(
        owasp_asi=["ASI-01"],
        art_detail=ARTAlignment(
            category=ARTBehaviorCategory.PROHIBITED_INFO,
            attack_vector=ARTAttackVector.INDIRECT,
        ),
    )
    assert fm.art == ["category:prohibited_info", "vector:indirect"]


def test_framework_mapping_art_includes_specific_behavior_and_strategy() -> None:
    fm = FrameworkMapping(
        owasp_asi=["ASI-01"],
        art_detail=ARTAlignment(
            category=ARTBehaviorCategory.CONFIDENTIALITY_BREACH,
            behavior=ARTBehavior.LEAK_USER_INFO,
            attack_vector=ARTAttackVector.DIRECT,
            attack_strategy=ARTAttackStrategy.FAUX_REASONING,
        ),
    )
    assert fm.art == [
        "category:confidentiality_breach",
        "vector:direct",
        "behavior:leak_user_info",
        "strategy:faux_reasoning",
    ]


def test_art_alone_does_not_make_finding_publishable() -> None:
    """ART is a benchmark cross-reference, not a primary taxonomy."""
    fm = FrameworkMapping(
        art_detail=ARTAlignment(
            category=ARTBehaviorCategory.PROHIBITED_ACTION,
            attack_vector=ARTAttackVector.INDIRECT,
        ),
    )
    assert fm.is_mapped() is False


# ---------------------------------------------------------------------------
# JSON round-trip for research consumers
# ---------------------------------------------------------------------------


def test_framework_mapping_json_round_trip_preserves_art_detail() -> None:
    """art_detail survives serialize/deserialize. The derived ``art`` tag list
    is also present in the JSON output (computed_field is included by default
    in pydantic v2 model_dump).
    """
    original = FrameworkMapping(
        owasp_asi=["ASI-01"],
        mitre_atlas=["AML.T0051"],
        art_detail=ARTAlignment(
            category=ARTBehaviorCategory.CONFIDENTIALITY_BREACH,
            behavior=ARTBehavior.LEAK_USER_INFO,
            attack_vector=ARTAttackVector.DIRECT,
            attack_strategy=ARTAttackStrategy.SYSTEM_PROMPT_OVERRIDE,
            notes="Direct chat exfiltration of patient records.",
        ),
    )
    blob = original.model_dump_json()

    # Sanity-check the wire shape research consumers will see.
    assert '"art_detail":' in blob
    assert '"art":[' in blob
    assert '"category":"confidentiality_breach"' in blob
    assert '"behavior":"leak_user_info"' in blob

    restored = FrameworkMapping.model_validate_json(blob)
    assert restored == original
    assert restored.art == original.art


# ---------------------------------------------------------------------------
# Finding integration: art_detail is optional and backward-compatible
# ---------------------------------------------------------------------------


def _evidence() -> Evidence:
    return Evidence(request="hi", response="bye")


def _manifest() -> ReproducibilityManifest:
    return ReproducibilityManifest(
        attack_name="demo",
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


def test_finding_constructs_without_art_detail() -> None:
    """Backward compatibility: existing Findings with no ART tag still validate."""
    f = Finding(
        attack_name="demo",
        target_id="mcp-local",
        verdict=Verdict.SUCCESS,
        severity=Severity.HIGH,
        severity_base=7.5,
        title="Demo",
        summary="Demo finding.",
        mappings=FrameworkMapping(owasp_asi=["ASI-01"]),
        evidence=_evidence(),
        manifest=_manifest(),
    )
    assert f.mappings.art_detail is None
    assert f.mappings.art == []


def test_finding_carries_art_detail_when_provided() -> None:
    f = Finding(
        attack_name="demo",
        target_id="mcp-local",
        verdict=Verdict.SUCCESS,
        severity=Severity.HIGH,
        severity_base=7.5,
        title="Demo",
        summary="Demo finding.",
        mappings=FrameworkMapping(
            owasp_asi=["ASI-01"],
            art_detail=ARTAlignment(
                category=ARTBehaviorCategory.PROHIBITED_ACTION,
                attack_vector=ARTAttackVector.INDIRECT,
            ),
        ),
        evidence=_evidence(),
        manifest=_manifest(),
    )
    assert f.mappings.art_detail is not None
    assert f.mappings.art == ["category:prohibited_action", "vector:indirect"]
