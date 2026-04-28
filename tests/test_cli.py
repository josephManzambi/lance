"""CLI tests for ``lance run``.

Covers the authorization-gate short-circuit, the ``--probe`` round-trip
and the stubbed-attack NotImplementedError path. The probe and attack
tests spawn the real vulnerable reference server, so they are marked
``integration``.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lance.cli import _PROBE_INPUT, app

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET_YAML = REPO_ROOT / "examples" / "mcp_vulnerable" / "target.yaml"


@pytest.fixture()
def at_repo_root(monkeypatch: pytest.MonkeyPatch) -> Path:
    """Chdir to REPO_ROOT so the target's relative ``command`` resolves and
    the example allowlist (which contains ``localhost``) is picked up.
    """
    monkeypatch.chdir(REPO_ROOT)
    return REPO_ROOT


def test_run_rejects_unauthorized_host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "authorized_targets.yaml").write_text(
        "authorized:\n  - localhost\n", encoding="utf-8"
    )
    evil = tmp_path / "evil.yaml"
    evil.write_text(
        "target_id: evil\n"
        "type: mcp\n"
        "transport: stdio\n"
        "host: evil.example.com\n"
        'command: ["true"]\n'
        "deployment:\n  iam_role_arn: null\n",
        encoding="utf-8",
    )
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "run",
            "--target",
            str(evil),
            "--attack",
            "indirect-injection-via-tool-output",
        ],
    )
    assert result.exit_code == 2
    assert "Authorization error" in result.stdout


@pytest.mark.integration
def test_run_probe_prints_target_turn_json(at_repo_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "run",
            "--target",
            str(TARGET_YAML),
            "--attack",
            "indirect-injection-via-tool-output",
            "--probe",
        ],
    )
    assert result.exit_code == 0, result.stdout
    payload = json.loads(_extract_json_block(result.stdout))
    assert payload["input"] == _PROBE_INPUT
    # The probe must surface fixture content end-to-end, not just a stub reply.
    assert "$12.4M" in payload["response"]
    assert payload["tool_calls"][0]["name"] == "read_document"
    assert payload["tool_calls"][0]["arguments"] == {"doc_id": _PROBE_INPUT}
    assert payload["raw_transcript"] is not None
    assert any(msg["role"] == "tool" for msg in payload["raw_transcript"])


@pytest.mark.integration
def test_run_stub_attack_exits_cleanly(at_repo_root: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "run",
            "--target",
            str(TARGET_YAML),
            "--attack",
            "indirect-injection-via-tool-output",
            "--include-unstable",
        ],
    )
    assert result.exit_code == 0, result.stdout
    assert "not implemented" in result.stdout.lower()


def _extract_json_block(stdout: str) -> str:
    start = stdout.index("{")
    depth = 0
    for idx in range(start, len(stdout)):
        ch = stdout[idx]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return stdout[start : idx + 1]
    raise AssertionError("No balanced JSON block in stdout")
