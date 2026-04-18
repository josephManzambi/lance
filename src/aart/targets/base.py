"""Target protocol — the abstraction for anything AART can attack.

A Target is an agentic system under test. It knows how to:
- Receive an adversarial input and return a response.
- Report the tool calls it made during the interaction.
- Expose its deployment context (IAM role, tools, etc.) for AART to analyze.

New target types (LangChain agent, CrewAI crew, custom HTTP agent, etc.)
implement this protocol in their own file under `targets/`.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field


class TargetTurn(BaseModel):
    """One round-trip interaction with a Target."""

    model_config = ConfigDict(frozen=True)

    input: str = Field(description="Input sent to the target — possibly adversarial.")
    response: str = Field(description="Target's final natural-language response.")
    tool_calls: list[dict[str, object]] = Field(
        default_factory=list,
        description="Tool calls made by the agent during this turn, in order.",
    )
    raw_transcript: str | None = Field(
        default=None,
        description="Full interaction transcript if the target can provide one.",
    )


class TargetContext(BaseModel):
    """Static properties of the target's deployment.

    Used by context/ probes to reason about blast radius. Populated once per
    target instance, cached across attack runs.
    """

    model_config = ConfigDict(frozen=True)

    target_type: str = Field(description="e.g. 'mcp', 'langchain', 'crewai'.")
    target_id: str = Field(description="Human-readable identifier from the target config.")

    # Agent capabilities
    available_tools: list[str] = Field(
        default_factory=list,
        description="Tool names the agent has access to.",
    )

    # Cloud binding (optional — populated by context/aws.py etc.)
    iam_role_arn: str | None = None

    # Arbitrary deployment metadata
    metadata: dict[str, str] = Field(default_factory=dict)


@runtime_checkable
class Target(Protocol):
    """The AART target protocol.

    Implementations live in `targets/<type>.py`. They are NOT Pydantic models
    (they hold connections, sessions, etc.), but every method that crosses
    a module boundary must accept/return Pydantic models.

    Implementations must be async — all target interactions go through
    async I/O so AART can parallelize attacks without threading.
    """

    @property
    def context(self) -> TargetContext:
        """Static deployment context for this target.

        Should be populated at construction time and not change across runs.
        """
        ...

    async def interact(self, user_input: str) -> TargetTurn:
        """Send a single user input to the target and return the interaction.

        The target handles its own system prompt, tool execution, memory —
        AART treats it as a black box that takes a string and returns a TargetTurn.

        Raises:
            TargetUnreachableError: if the target cannot be contacted.
            TargetTimeoutError: if the target does not respond in time.
        """
        ...

    async def reset(self) -> None:
        """Reset any per-conversation state (memory, tool call history).

        Called between independent attack attempts to ensure runs are isolated.
        """
        ...


class TargetError(Exception):
    """Base error for Target protocol implementations."""


class TargetUnreachableError(TargetError):
    """The target could not be contacted (network error, wrong URL, auth failure)."""


class TargetTimeoutError(TargetError):
    """The target did not respond within the configured timeout."""


class TargetAuthorizationError(TargetError):
    """The target config points at a host not explicitly authorized.

    Raised before any network call to a non-whitelisted target. This is the
    safety rail that prevents AART from being turned into an unauthorized
    attack tool.
    """
