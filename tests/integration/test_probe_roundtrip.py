"""End-to-end probe round-trip integration test.

Spawns the real ``examples/mcp_vulnerable/server.py`` subprocess via the
example target config and asserts that the probe input
(:data:`lance.cli._PROBE_INPUT`) drives a complete transport + tool
execution path and that fixture content (the Q3 2025 revenue figure)
round-trips back into the response.

This is the canary that detects silent breakage in the v0.1 round-trip:
empty fixtures, broken tool dispatch, or transcript regressions all
manifest here as concrete failures rather than confabulated success.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

import pytest

from lance.cli import _PROBE_INPUT
from lance.targets.config import TargetConfig
from lance.targets.mcp import MCPTarget

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET_YAML = REPO_ROOT / "examples" / "mcp_vulnerable" / "target.yaml"


@pytest.fixture()
def at_repo_root(monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.chdir(REPO_ROOT)
    return REPO_ROOT


@pytest.mark.integration
def test_probe_roundtrip_quotes_fixture_revenue_figure(at_repo_root: Path) -> None:
    if shutil.which("uv") is None:
        pytest.skip("uv not on PATH; cannot spawn the example MCP server")

    async def _run() -> None:
        config = TargetConfig.load(TARGET_YAML)
        target = await MCPTarget.from_config(config)
        try:
            turn = await target.interact(_PROBE_INPUT)
        finally:
            await target.aclose()

        # Tool dispatch reaches the real read_document with the fixture id.
        assert len(turn.tool_calls) == 1
        call = turn.tool_calls[0]
        assert call["name"] == "read_document"
        assert call["arguments"] == {"doc_id": _PROBE_INPUT}
        assert call["is_error"] is False

        # Fixture content actually transited the transport. If this regresses
        # to a confabulated reply, the model never read the document.
        assert "$12.4M" in turn.response

        # raw_transcript records the v0.1 [user, tool] exchange.
        assert turn.raw_transcript is not None
        assert len(turn.raw_transcript) >= 2
        roles = [msg["role"] for msg in turn.raw_transcript]
        assert "user" in roles
        assert "tool" in roles

    asyncio.run(_run())
