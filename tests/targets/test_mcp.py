"""Integration tests for MCPTarget via stdio transport.

Spawns the real ``examples/mcp_vulnerable/server.py`` subprocess. Marked
``integration`` because it involves process creation.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from mcp.client.stdio import StdioServerParameters

from lance.targets.base import TargetContext, TargetTurn, TargetUnreachableError
from lance.targets.config import TargetConfig
from lance.targets.mcp import MCPTarget

REPO_ROOT = Path(__file__).resolve().parents[2]
TARGET_YAML = REPO_ROOT / "examples" / "mcp_vulnerable" / "target.yaml"
ALLOWLIST_CONTENT = "authorized:\n  - localhost\n"


@pytest.fixture()
def allowlist(tmp_path: Path) -> Path:
    path = tmp_path / "authorized_targets.yaml"
    path.write_text(ALLOWLIST_CONTENT, encoding="utf-8")
    return path


def _load_config(allowlist: Path) -> TargetConfig:
    return TargetConfig.load(TARGET_YAML, allowlist_path=allowlist)


@pytest.mark.integration
def test_interact_returns_populated_target_turn(allowlist: Path) -> None:
    async def _run() -> None:
        config = _load_config(allowlist)
        target = await MCPTarget.from_config(config)
        try:
            turn = await target.interact("ping")
        finally:
            await target.aclose()

        assert isinstance(turn, TargetTurn)
        assert turn.input == "ping"
        assert turn.response == "pong"
        assert len(turn.tool_calls) == 1
        call = turn.tool_calls[0]
        assert call["name"] == "read_document"
        assert call["arguments"] == {"doc_id": "ping"}
        assert call["is_error"] is False
        assert call["result"] == "pong"

        # raw_transcript should reflect the v0.1 [user, tool] exchange.
        assert turn.raw_transcript is not None
        assert len(turn.raw_transcript) == 2
        user_msg, tool_msg = turn.raw_transcript
        assert user_msg == {"role": "user", "content": "ping"}
        assert tool_msg["role"] == "tool"
        assert tool_msg["name"] == "read_document"
        assert tool_msg["arguments"] == {"doc_id": "ping"}
        assert tool_msg["content"] == "pong"
        assert tool_msg["is_error"] is False

    asyncio.run(_run())


@pytest.mark.integration
def test_available_tools_populated_from_list_tools(allowlist: Path) -> None:
    async def _run() -> None:
        config = _load_config(allowlist)
        target = await MCPTarget.from_config(config)
        try:
            assert "read_document" in target.context.available_tools
            assert target.context.target_type == "mcp"
            assert target.context.target_id == "mcp-vulnerable-local"
        finally:
            await target.aclose()

    asyncio.run(_run())


@pytest.mark.integration
def test_reset_clears_and_reopens_session(allowlist: Path) -> None:
    async def _run() -> None:
        config = _load_config(allowlist)
        target = await MCPTarget.from_config(config)
        try:
            first = await target.interact("welcome")
            await target.reset()
            second = await target.interact("welcome")
        finally:
            await target.aclose()

        assert first.response == second.response
        assert first.response.startswith("Welcome to the LANCE reference target")

    asyncio.run(_run())


def test_interact_before_construction_raises() -> None:
    async def _run() -> None:
        # Hand-build a target with no session to exercise the guard.
        ctx = TargetContext(
            target_type="mcp",
            target_id="unused",
            available_tools=["noop"],
        )
        target = MCPTarget(ctx, StdioServerParameters(command="false"))
        with pytest.raises(TargetUnreachableError, match="session is not open"):
            await target.interact("x")

    asyncio.run(_run())
