# ART Benchmark Alignment

LANCE Findings can optionally be tagged with metadata aligning them to the
**Agent Red Teaming (ART)** benchmark introduced by Zou et al.,
*"Security Challenges in AI Agent Deployment: Insights from a Large Scale
Public Competition"* ([arXiv:2507.20526](https://arxiv.org/abs/2507.20526),
Gray Swan AI + UK AI Security Institute, July 2025).

## Why

ART is a curated benchmark of 4,700 adversarial prompts across 44 deployment
scenarios, used to score frontier LLMs on a private leaderboard. Tagging
LANCE Findings with ART taxonomy makes them cross-referenceable with that
leaderboard and with future tooling built around the benchmark.

LANCE and ART occupy different niches:

- **ART** evaluates models against a fixed corpus of attacks in simulated
  scenarios.
- **LANCE** generates novel attacks against real, user-authorized MCP
  deployments and produces Findings with reproducibility manifests and IAM
  blast-radius context.

Tagging LANCE Findings with ART metadata bridges the two.

## What we use from ART

- The **4 top-level behavior categories** (paper §2.1, verbatim):
  Confidentiality Breaches, Conflicting Objectives, Prohibited Info,
  Prohibited Actions.
- The **direct/indirect attack-vector axis** (§2.1).
- The **5 example behaviors** disclosed in Appendix A. The remaining 39 of
  the 44 sit on Gray Swan's private leaderboard and are not enumerated here.
- The **3 named universal attack strategies** from §3.4.2: System Prompt
  Overrides, Faux Reasoning, New Session / Session Data Update.

> Naming note: the paper itself is internally inconsistent — Table 1 says
> "Prohibited Content" while §2.1 says "Prohibited Info"; Appendix A uses
> singular "Prohibited Action" while §2.1 uses "Prohibited Actions". LANCE
> pins the §2.1 wording (`PROHIBITED_INFO`, `PROHIBITED_ACTION`) since §2.1
> is the canonical taxonomy section.

## What we don't import

- The ART **attack corpus** itself. Per LANCE's research-integrity rules
  ([CLAUDE.md §6](../../CLAUDE.md)), attacks are generated de novo from
  primitives, never scraped. The corpus is also not openly distributed.
- The paper PDF. Reference by arXiv ID only.

## Schema

The canonical types live in [`src/lance/taxonomy/art.py`](../../src/lance/taxonomy/art.py):

- `ARTBehaviorCategory` — the 4 §2.1 categories.
- `ARTAttackVector` — `direct` or `indirect`.
- `ARTBehavior` — the 5 disclosed Appendix-A behaviors plus `OTHER`. Use
  `OTHER` for LANCE Findings that don't map to a disclosed behavior; do not
  invent new members until Gray Swan publishes them.
- `ARTAttackStrategy` — the 3 §3.4.2 named strategies.
- `ARTAlignment` — the structured `(category, behavior, vector, strategy,
  notes)` tuple.

`FrameworkMapping` carries two ART-related fields:

- `art_detail: ARTAlignment | None` — the structured object (source of truth).
- `art: list[str]` — a derived, read-only computed field that produces flat
  prefixed tags (`category:…`, `vector:…`, optionally `behavior:…`,
  optionally `strategy:…`) suitable for leaderboard cross-referencing.
  `behavior:other` is intentionally omitted from this list since it carries
  no leaderboard value; the structured `art_detail` still records it.

ART tagging does **not** make a Finding publishable on its own —
`FrameworkMapping.is_mapped()` still requires at least one primary-taxonomy
mapping (OWASP ASI, MITRE ATLAS, or CSA AICM). ART is a benchmark
cross-reference, not a primary taxonomy.

## Construction-time requirement

`Finding` is frozen. `art_detail` must be populated **at Finding construction
time** — there is no setter to backfill it later. Attack authors should
decide the mapping when their attack module emits the Finding.

## Follow-up: tagging existing attacks

Each attack module is responsible for declaring its own ART mapping. For
example, `lance.attacks.indirect_injection` is an obvious
`ARTAttackVector.INDIRECT` candidate; whether it maps to `PROHIBITED_ACTION`
or `PROHIBITED_INFO` depends on the specific instance. Mapping is left to
the attack author rather than imposed top-down.
