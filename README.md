# LANCE — Lateral Agentic eNvironment Cloud Exploitation

Cloud-native red-teaming framework for deployed agentic AI systems.

LANCE attacks agents the way real adversaries do — through tool outputs, RAG sources, and MCP connections — and traces the blast radius through the cloud deployment context (IAM roles, data access, logging posture).

> **Status:** pre-release. v0.1 in development. Not ready for production use.

## What LANCE tests

- **Targets:** MCP servers with AWS-backed tools *(v0.1)*
- **Attack classes:** Indirect prompt injection through tool outputs *(v0.1)*
- **Context probes:** IAM role blast-radius analysis

Findings are cross-referenced with [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/), [MITRE ATLAS](https://atlas.mitre.org/), and the CSA AI Controls Matrix.

See [`VISION.md`](./VISION.md) for the design thesis and scope.

## Design principles

1. **Sovereignty** — local-first, no telemetry, runs offline.
2. **Reproducibility** — every finding ships with a manifest.
3. **Mappings everywhere** — OWASP ASI, MITRE ATLAS, CSA AICM on every finding.
4. **Honest findings** — flaky attacks are disabled, not hidden.

## Install

Requires Python ≥ 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/josephManzambi/lance.git
cd lance
uv sync
```

For local LLM judges, install [Ollama](https://ollama.com/) and pull a model:

```bash
ollama pull qwen2.5:72b   # or llama3.3:70b
```

## Quick start

```bash
# Run an attack against a target you've authorized
uv run lance run \
  --target examples/mcp_local.yaml \
  --attack indirect_injection \
  --output findings/
```

See [`docs/getting-started.md`](./docs/getting-started.md) for a walkthrough.

## Contributing

LANCE uses a strict contributor contract. Read [`CLAUDE.md`](./CLAUDE.md) before submitting changes — it applies to human contributors as well as AI-assisted development.

New attacks follow the contract in §7 of `CLAUDE.md`.

## Research integrity

LANCE findings are intended for public citation. Attacks must:

- Declare their framework mappings (OWASP ASI, MITRE ATLAS, CSA AICM)
- Include a threat-model docstring
- Produce findings with a reproducibility manifest

Flaky or unreviewed attacks are disabled by default.

## License

Apache 2.0. See [`LICENSE`](./LICENSE).

## Citing LANCE

If LANCE contributed to a publication, please cite as:

```
Manzambi, J. (2026). LANCE: Lateral Agentic eNvironment Cloud Exploitation.
https://github.com/josephManzambi/lance
```

## Author

Joseph Manzambi — Cloud & AI Security, Málaga.
