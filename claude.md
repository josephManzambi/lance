# CLAUDE.md — Lance

Read this file completely at the start of every session. When what you think is best conflicts with what this file says, this file wins. No exceptions.

---

## 0. Project map

**Lance** (Lateral Agentic eNvironment Cloud Exploitation)
Cloud-native red-teaming framework for *deployed* agentic AI systems. Tests agents as they are actually deployed — with their tool chain, IAM roles, and cloud context. Defender's instrument.

---

## 1. Who is building this

Joseph Manzambi. Cloud security specialist (AWS), vCISO trajectory. CAISS certified. Based in Málaga.

This code will be cited in public research. Every architectural choice and every Finding it produces will be attributed to this project. The bar is research-grade, not production-grade MVP. The difference: reproducibility and honesty are requirements, not nice-to-haves.

---

## 2. Absolute rules — never break these

**2.1 No telemetry. No phone-home. No remote analytics.**
Not opt-in, not anonymized, not "just a ping." Never. Sovereignty is a brand commitment.

**2.2 Local-first by default.**
Lance must run fully offline on a MacBook Pro M5 Max with Ollama. Cloud calls are only allowed when explicitly targeting an authorized system. Internet access is never assumed.

**2.3 Authorization before any network call.**
Lance: If a target config points at anything other than localhost, 127.0.0.1, *.local, or the explicit authorized_targets.yaml allowlist — raise TargetAuthorizationError before touching the network. No exceptions, no overrides, no "trust me" flags.

**2.4 Never swallow exceptions in attack or evaluation code.**
No bare `except: pass`. No `except Exception as e: logger.debug(e)` in attack/challenge code. Failures surface fully. A hidden failure produces a misleading result, which is worse than no result.

**2.5 All public-facing types are Pydantic v2 models. mypy --strict passes.**
No Any without an inline comment explaining why it's unavoidable. No untyped function signatures.

**2.6 No hardcoded credentials anywhere.**
Not in code, not in tests, not in fixtures, not in doc examples. Use pydantic-settings + .env (gitignored). If a test needs a credential, it uses a fake one explicitly labeled as such.

**2.7 Judge verdicts are structured Pydantic models, not free text.**
Never return a raw LLM string as a verdict. Parse it. If parsing fails, that is a JudgeError, not a FAILED verdict.

**2.8 Results must be reproducible.**
Every Lance Finding includes a manifest: model version, seed, exact prompts, environment hash, timestamp. If the manifest is incomplete, the result is not publishable. Period.

**2.9 No commits with failing tests, failing mypy, or failing ruff.**
Stop before committing. Tell the human what's broken. Do not use --no-verify.

---

## 3. Before writing code — always

1. If the task touches more than 2 files → use plan mode, show the plan, wait for confirmation.
2. If you're adding a new dependency → check pyproject.toml first. New deps require explicit human approval. Keep the list short.
3. If the file you're editing has no tests → write the tests first.
4. If the task is "clean up" or "refactor" without a stated problem → stop and ask what problem we're solving. Unprompted refactors are forbidden.
5. If the task modifies a base protocol (targets/base.py, attacks/base.py, judges/base.py) → ask for written justification before touching it.

---

## 4. Architecture

```
src/
└── lance/                   # Red-teaming framework
    ├── models/              # Pydantic models: Finding, ReproducibilityManifest, etc.
    ├── targets/             # Target protocol + adapters (mcp.py, langchain.py, ...)
    ├── attacks/             # Attack plugins (one file per attack class)
    ├── judges/              # Judge protocol + implementations (llm_judge.py, ...)
    ├── context/             # Cloud deployment probes (aws.py, ...)
    ├── mappings/            # Framework references (owasp_asi.py, mitre_atlas.py, csa_aicm.py)
    ├── report/              # Output formatters (manifest.py, markdown.py)
    └── cli.py               # Typer CLI — thin wiring only

tests/
└── lance/
    ├── attacks/
    ├── targets/
    └── test_finding.py
```

**Import rules (strict):**
- `cli.py` is wiring only. No business logic.
- No circular imports. If you're tempted to fix one with a local import, restructure instead.

---

## 5. Lance — attack authoring contract

Every new attack module **must**:

1. Live in `src/lance/attacks/<snake_case>.py`
2. Subclass `Attack` from `attacks/base.py`
3. Declare as class attributes:
   - `name: ClassVar[str]` — unique kebab-case id
   - `description: ClassVar[str]` — threat model: which attacker, which assumption, which objective
   - `owasp_asi: ClassVar[list[str]]` — at least one, e.g. `["ASI-01"]`
   - `mitre_atlas: ClassVar[list[str]]` — may be empty only if genuinely N/A
   - `csa_aicm: ClassVar[list[str]]` — may be empty only if genuinely N/A
   - `stable: ClassVar[bool]` — False = excluded from default runs
4. Implement `async def run(self, target: Target, config: AttackConfig) -> Finding`
5. Have at least one test using a FakeTarget fixture
6. Never import a concrete Target subclass — always accept the Target protocol

The `__init_subclass__` enforcement in `Attack` base class will raise `TypeError` at import time if these contract items are missing. This is intentional.

---

## 6. Research integrity rules

These exist because Lance Findings will be publicly cited. A wrong result is worse than no result.

- Every Finding includes a complete ReproducibilityManifest (prompts, model, seed, config hash, platform, timestamp). Incomplete manifests = not publishable.
- Attack success criteria must be in the attack's source code, not inferred by the judge alone. The judge's rubric is part of the Finding.
- Flaky attacks (< 80% consistency across 5 runs) are marked `stable = False` and excluded from default runs.
- Never summarize a negative result as "no vulnerability found." Record the actual verdict (FAILED/ERROR) with full evidence.

---

## 7. Stack and conventions

- **Python ≥ 3.12**
- **Package manager:** `uv` (not pip, not poetry). Commands: `uv sync`, `uv run pytest`, `uv add <pkg>`.
- **Data models:** Pydantic v2. All cross-module data is a Pydantic model.
- **CLI:** Typer (entrypoint: `lance`).
- **Testing:** pytest + pytest-cov. Target coverage ≥ 85% for attacks/, judges/.
- **Lint/format:** Ruff (handles both). Config in pyproject.toml.
- **Types:** mypy strict.
- **Storage:** SQLite for run results, JSON for manifests, YAML for configs.
- **Local LLM:** Ollama. Default attacker/judge: `qwen2.5:72b` or `llama3.3:70b`. Fully configurable. No hard-coded model choices.
- **Docs:** MkDocs Material. Every public function has a Google-style docstring.
- **Commit style:** Conventional commits. Allowed types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `security`, `bench`. Scope: `(lance)`. Max 72 chars subject line. English, imperative mood.

---

## 8. Anti-patterns — refuse these

If asked to implement any of the following, push back and ask the human to confirm explicitly:

- Web UI, dashboard, or REST API for v0.1
- Automated remediation suggestions in Lance (Findings describe; humans prescribe)
- Retry loops around LLM calls that silently mask failures
- Any cache of LLM responses that could make reproducibility manifests misleading
- Importing `langchain`, `llama-index`, `transformers`, or any heavy ML framework into core code (we talk to models via Ollama or HTTP; we don't run them)
- "Run all attacks" without authorization check
- Modifying base protocols without written justification

---

## 9. When you're unsure

Ask. Specifically:

- If attack correctness is ambiguous → ask before implementing
- If a design choice affects the public API or result schema → ask
- If you're about to add a dep that brings in network calls → ask
- If a test is flaky → mark it `@pytest.mark.flaky`, disable it, and tell the human

The human running this project is building public research artifacts that will be cited. Assume high standards and a preference for doing less, well, over more, fast.
