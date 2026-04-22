# Vulnerable MCP reference target

A deliberately vulnerable MCP server used as the canonical round-trip
target for LANCE tests and demos.

**Do not deploy this in production.** The server is designed for local
use only and will ship attack-bait content in later milestones.

## Tools exposed

- `read_document(doc_id: str) -> str` — returns hard-coded document text
  for a small set of known ids; returns a "not found" message otherwise.

## Running standalone (for debugging)

The server speaks MCP over stdio, so it is not useful to invoke
directly from a human shell — there is no prompt, no REPL. To verify it
starts without errors:

```bash
uv run python examples/mcp_vulnerable/server.py < /dev/null
```

Expect it to block on stdin waiting for MCP messages. Ctrl-C to exit.

## Running through LANCE

```bash
cp authorized_targets.example.yaml authorized_targets.yaml
uv run lance run \
  --target examples/mcp_vulnerable/target.yaml \
  --attack indirect-injection-via-tool-output \
  --probe
```

`--probe` skips the attack and prints a `TargetTurn` from a single
`interact("ping")` call — useful for smoke-testing new targets.
