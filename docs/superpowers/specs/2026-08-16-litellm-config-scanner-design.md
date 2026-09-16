# LiteLLM Config Scanner — Design

## Context

`secureai-scan` currently references LiteLLM in two places only: as a detected LLM SDK client (regex patterns in `python-scanner.ts`) and as a DEP003 dependency-advisory target (CVEs in `advisories-generated.ts`). It has no awareness of LiteLLM's own proxy configuration (`config.yaml`) the way it already does for MCP client configs (`.mcp.json`, `claude_desktop_config.json`, etc. via `mcp-config-scanner.ts`).

This is the first of two planned LiteLLM-related sub-projects. The second — a runtime guardrail hook that plugs into LiteLLM Proxy's `CustomGuardrail` interface to block/flag requests live — is out of scope for this spec and will get its own design later.

## Goal

Statically scan LiteLLM proxy `config.yaml` files for parsed, factual misconfigurations: hardcoded secrets, plaintext transport to remote providers, and (as a low-confidence nudge only) the complete absence of a `guardrails:` section. This is the literal thing the user asked for ("something that works in litellm for guardrails") in its static form — a first pass that ships fast, in this repo's existing architecture, before the larger runtime component.

## Non-goals

- No runtime request-time behavior (that's the separate guardrail-hook sub-project).
- No general LiteLLM proxy config linting (auth toggles, database settings, spend-log config, etc.) — anything not specifically an LLM-security-relevant signal is out of scope, per this repo's fixed LLM/MCP/RAG detection scope (`CLAUDE.md` hard requirement #3).
- No evaluation of *which* guardrail provider is configured or whether it's well-configured beyond "does the section exist" — that would require provider-specific knowledge this scanner doesn't have and risks false confidence.

## Architecture

New self-contained module `src/scanner/litellm-config-scanner.ts`, following the exact pattern of `src/scanner/mcp-config-scanner.ts`:

- Off-disk file discovery and parsing — not part of the ts-morph `Project`, not AST-based.
- Walks the repo using the same skip-dir list as the MCP config scanner (`node_modules`, `.git`, `dist`, `build`, `out`, `.next`, `.venv`, `venv`, `__pycache__`), respecting `skipPaths` from policy config.
- Candidate files: any `*.yaml`/`*.yml`.
- **Structural gate before treating a file as a LiteLLM config**: the parsed YAML must have a top-level `model_list` key whose value is an array, where at least one entry has a `litellm_params` object. This is LiteLLM's own proxy config schema shape and is distinctive enough to avoid false-positiving on unrelated YAML files (e.g. a Kubernetes `config.yaml`, a generic app config). Files that parse but don't match this shape are silently skipped — no finding, no error.
- Parsing library: **new dependency `js-yaml`**, using its default schema (`load`, not `loadAll`/unsafe custom-tag schemas) — no JS-object/function deserialization tags, consistent with this codebase's existing concern about unsafe YAML deserialization (SKL010, skill-bundle metadata).
- Wired into `scan.ts` (`scanRepositoryDetailed`) and `src/scanner/rules/index.ts` the same way `CONFIG_RULE_IDS` is today (new `LITELLM_CONFIG_RULE_IDS` array feeding `AVAILABLE_RULE_IDS`).

## Rules

New rule-ID prefix: `LLC` (LiteLLM Config) — chosen to avoid colliding with the `LLMxx:2026` OWASP taxonomy labels already used in report output for the OWASP LLM Top 10 mapping (those are a separate `owasp` field, not the `rule_id`, but a distinct prefix keeps them unambiguous at a glance).

### LLC001 — Hardcoded secret in LiteLLM config
- **Evidence: `proven`, severity: critical.**
- Fires when any of these fields, under a `litellm_params` block or `general_settings`, hold a literal string value instead of an `os.environ/VAR_NAME` reference (LiteLLM's own convention for pulling secrets from the environment):
  - `api_key`
  - `master_key`
  - `salt_key`
  - other known integration credential fields following the same `*_api_key` / `*_key` naming used by LiteLLM's bundled integrations (Langfuse, Aporia, etc.)
- A value is treated as a literal secret if it does not match `^os\.environ/` and is not empty/placeholder-shaped (reuse the same minimum-length + non-placeholder heuristic MCP005 uses for `ENV_REFERENCE`/length gating, adapted to LiteLLM's `os.environ/X` syntax instead of `${...}`).
- Directly mirrors MCP005 (`src/scanner/mcp-config-scanner.ts`).

### LLC002 — Plaintext HTTP provider endpoint
- **Evidence: `proven`, severity: high.**
- Fires when an `api_base` value under `litellm_params` uses `http://` and the host is not localhost/loopback (same locality check as MCP006: `localhost`, `127.0.0.1`, `0.0.0.0`, `::1`).
- Directly mirrors MCP006.

### LLC003 — No guardrails configured
- **Evidence: `heuristic`, severity: low, hidden unless `--paranoid`.**
- Fires when a file passes the LiteLLM-config structural gate (real `model_list` with actual provider entries) and has no top-level `guardrails:` key at all.
- Deliberately the lowest evidence tier: absence of an optional feature is not itself a vulnerability, only a nudge. This keeps it out of default output and off the precision gate's `proven`/`likely` corpus requirement, consistent with `CLAUDE.md`'s evidence-tier contract (heuristic = pattern/proximity signal only, never asserted as a proven fact).

## Data flow

```
config.yaml (found via same walk pattern as MCP scanner)
  → js-yaml load()
  → structural gate (model_list + litellm_params present?)
      → no  → skip file, no finding
      → yes → walk model_list entries for LLC001/LLC002
            → check top-level guardrails key for LLC003
  → Finding[] (rule_id, file, line via same lineOf() line-anchoring approach as mcp-config-scanner.ts)
```

Line numbers: reuse the `lineOf(lines, needle)` approach from `mcp-config-scanner.ts` (find first line containing the matched key/value string) rather than tracking real YAML AST positions — js-yaml's default `load()` doesn't give node positions without extra options, and this repo's MCP scanner already accepts this approximation for JSON.

## Testing

Same checklist as any new rule, per `CLAUDE.md`'s "Adding a new rule":

1. Vulnerable fixtures: `test-fixtures/vulnerable/litellm-config-secret.yaml` (LLC001), `test-fixtures/vulnerable/litellm-config-http.yaml` (LLC002), `test-fixtures/vulnerable/litellm-config-no-guardrails.yaml` (LLC003, only visible under `--paranoid`).
2. Safe fixture: `test-fixtures/safe/litellm-config-clean.yaml` — all secrets as `os.environ/VAR`, `api_base` on `https://`, a populated `guardrails:` section. Must produce zero `proven`/`likely` findings.
3. A safe fixture for the structural gate itself: an unrelated `config.yaml` (e.g. a generic app config with a coincidental `model_list` string field, or no `litellm_params`) that must produce zero findings — proves the gate isn't name-matching alone.
4. Catalog entries (`src/scanner/catalog.ts`: title/owasp/impact/fix, `FRAMEWORK_MAP` if an MCP/ASI mapping is defensible — likely not, this is provider-gateway config, not MCP) and explainer entries (`src/scanner/explainer.ts`'s `DEFAULT_EXPLANATIONS`) for LLC001–003.
5. Extend `EXPECTED_VULNERABLE` in `test/corpus.test.js`.
6. `npm run build && npm test`, then `npm run regression` before considering the rule done (a real-world LiteLLM proxy repo would be a good regression-scan candidate if one exists in the current `.regression-cache/` set or can be added).

## Open item carried to implementation

The exact list of "known integration credential fields" for LLC001 beyond `api_key`/`master_key`/`salt_key` should be finalized by looking at LiteLLM's actual documented `litellm_params`/`general_settings` schema during implementation, not guessed here — this keeps the field list a citable fact rather than a guess (consistent with `CLAUDE.md`'s DEP003 advisory bar: "a plausible guess is not the same as a citable fact").
