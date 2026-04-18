"""Indirect prompt injection via tool output.

Threat model:
    An attacker who controls data returned by a tool the agent calls
    (e.g. a document in an S3 bucket, a web page fetched by a browsing tool,
    a record in a database) embeds instructions in that data. When the agent
    reads the tool output, the embedded instructions hijack the agent's
    subsequent behavior.

    This is a realistic attack against any agent whose tools fetch data from
    sources outside the agent's trust boundary — i.e., almost all production
    agents.

    OWASP ASI-01 territory (Memory Poisoning / Indirect Injection surface).

Current status:
    Stub — architecture placeholder. Implementation lands with v0.1.
    See VISION.md for scope.
"""

from __future__ import annotations

from typing import ClassVar

from lance.attacks.base import Attack, AttackConfig
from lance.models.finding import Finding
from lance.targets.base import Target


class IndirectInjectionViaToolOutput(Attack):
    """Inject instructions into tool output data and observe whether the agent follows them."""

    name: ClassVar[str] = "indirect-injection-via-tool-output"
    description: ClassVar[str] = (
        "Simulates an attacker who controls data returned by one of the agent's tools "
        "(e.g. a fetched document, a database row, an MCP resource). The attacker embeds "
        "instructions in that data; if the agent treats tool output as trusted context "
        "rather than untrusted data, the embedded instructions redirect the agent's behavior. "
        "A successful finding demonstrates both model-layer susceptibility AND cloud-layer "
        "blast radius via the exposed IAM role."
    )

    owasp_asi: ClassVar[list[str]] = ["ASI-01"]
    mitre_atlas: ClassVar[list[str]] = ["AML.T0051.000"]  # LLM Prompt Injection: Direct
    csa_aicm: ClassVar[list[str]] = []  # TODO: map to AICM controls in v0.1

    stable: ClassVar[bool] = False  # experimental until v0.1 implementation lands

    async def run(self, target: Target, config: AttackConfig) -> Finding:
        """Execute the attack. Implementation pending for v0.1.

        Planned flow:
        1. Generate an adversarial payload using the attacker_model, parameterized
           on target.context.available_tools so the payload targets a real tool
           the agent has access to.
        2. Place the payload where the agent will fetch it (details depend on
           target type — for MCP targets, via a controlled mock MCP resource).
        3. Call target.interact() with a benign-looking user query that triggers
           the tool call.
        4. Run the Judge on the resulting TargetTurn to decide verdict.
        5. Probe target.context.iam_role_arn for blast radius via context/aws.py.
        6. Package into a Finding with full manifest.
        """
        raise NotImplementedError(
            "IndirectInjectionViaToolOutput.run will be implemented in v0.1. "
            "See VISION.md and CLAUDE.md §7 for the implementation contract."
        )
