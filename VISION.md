# LANCE — Vision

## What LANCE is

LANCE (Lateral Agentic eNvironment Cloud Exploitation) is a red-teaming framework for **deployed agentic AI systems**. It attacks agents the way a real adversary would: through their tool outputs, their RAG sources, their MCP connections — and it traces the damage through the cloud deployment they live in.

## What LANCE is not

- Not a general-purpose LLM safety evaluator. (Use Garak, DeepTeam, Giskard.)
- Not a model capability benchmark. (That's a sister project, not this one.)
- Not a hosted service. LANCE runs on your machine, against targets you authorize.
- Not an automated remediation tool. Findings describe; humans prescribe.

## Why LANCE exists

Existing agentic red-team tools test **the model's response to adversarial prompts**. Real breaches don't stop there. A prompt injection that causes an agent to invoke the wrong tool is only a vulnerability if the tool's IAM role, data access, and logging posture turn it into an exploitable blast radius.

LANCE's contribution: **cloud-context-aware findings.** When we report a prompt injection, we report it together with the IAM policy that made it dangerous.

## Scope: v0.1

- **Target type:** MCP servers with AWS-backed tools.
- **Attack class:** Indirect prompt injection through tool outputs (OWASP ASI-01 territory).
- **Context probes:** IAM role blast-radius analysis for the target's deployment.
- **Outputs:** JSON reproducibility manifest + Markdown finding report with framework mappings.
- **Execution:** Local CLI only. Offline by default. No telemetry.

## Scope: v0.2+ (sketch, not commitment)

- Second attack class (memory manipulation or tool chain hijacking).
- LangChain/CrewAI target adapters.
- Context probes for GCP and Azure.
- Attacker-model adapters for Anthropic/OpenAI APIs (opt-in, still local-default).

## Design principles

1. **Sovereignty** — local-first, no telemetry, runs offline.
2. **Reproducibility** — every finding ships with a manifest that lets anyone re-run it.
3. **Honesty** — if an attack is flaky, it's disabled, not hidden.
4. **Mappings everywhere** — every finding cross-references OWASP ASI 2026, MITRE ATLAS, and CSA AICM. We don't invent new taxonomies; we connect existing ones.
5. **Clean abstractions** — Target, Attack, Judge are protocols, not concrete classes. New contributors add files, not modify protocols.

## What "done" looks like for v0.1

- `lance run --target examples/mcp_vulnerable.yaml --attack indirect_injection` executes end-to-end.
- Produces a `Finding` JSON manifest and a human-readable Markdown report.
- At least one reproduced public-interest finding from a deliberately vulnerable MCP server we stand up ourselves.
- Tests pass. Mypy --strict passes. Docs build.
- One blog post analyzing the finding, with LANCE credited as the tool used (not the headline).
