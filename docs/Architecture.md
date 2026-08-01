# Architecture

SecureAI-Scan runs four independent scanning surfaces and merges their output into one finding list. Each surface exists because the source material is fundamentally different — an AST for TypeScript, text for Python, JSON for MCP config, a whole directory for Agent Skills — and forcing them through one abstraction would weaken all four.

## The four surfaces

### 1. TypeScript/JavaScript — AST-based (`src/scanner/project.ts`, `src/scanner/rules/*.ts`)

`src/scanner/project.ts` builds one [`ts-morph`](https://ts-morph.com/) `Project` from the target path (`skipAddingFilesFromTsConfig: true`, excluding `node_modules`/`dist`/`build`/`out`/`.next`). Every rule in `src/scanner/rules/` is a `Rule` object (`id`, `title`, `severity`, `run(context)`) that walks this AST independently — rules do not share a traversal pass, each does its own `forEachDescendant`-style walk.

The defining property of this surface: **a call is only ever treated as "an LLM call" if it resolves through actual import bindings to a known SDK** (`resolveLlmSink` in `src/scanner/rules/llm-rule-utils.ts` — covers `openai`, `@anthropic-ai/sdk`, `ai`, `@google/genai`, LangChain, Bedrock, and others). A function named `query()` or `chat()` that isn't imported from one of those packages is never flagged, no matter how LLM-shaped its name looks. This is the single biggest lever against false positives in the whole project — see [DetectionEngine.md](DetectionEngine.md) for why.

### 2. Python — regex + taint propagation (`src/scanner/python-scanner.ts`)

Python has no AST pass here — patterns for LLM SDK calls, request-input taint sources, vector-store calls, and exec-style sinks are matched line-by-line, with a small taint-propagation pass connecting a source line to a sink line within the same file. This is a real trade-off, not an oversight: regex matching is inherently more prone to context-free false positives than an AST + import resolution (see the MCP001 false-positive class in [DetectionEngine.md](DetectionEngine.md), which was exactly this). [`ROADMAP.md`](../ROADMAP.md) tracks the plan to move this to full AST analysis; a working spike lives in `spike/python-ast-poc/` (tree-sitter-based, not yet wired into `src/`).

### 3. Config and content files — read directly off disk (`src/scanner/mcp-config-scanner.ts`, `src/scanner/skill-scanner.ts`)

These two scanners don't go through the ts-morph `Project` at all — they read files directly:

- **`mcp-config-scanner.ts`** parses `.mcp.json`, `claude_desktop_config.json`, and `.cursor/mcp.json` as JSON, producing `MCP004`–`MCP006` (unpinned `npx -y` servers, inline secrets, plaintext HTTP transports).
- **`skill-scanner.ts`** walks an Agent Skill bundle (a directory containing `SKILL.md`) and produces `SKL001`–`SKL005`, reusing the invisible-Unicode/injection-phrase/cross-reference checks in `tool-poisoning-checks.ts` that the MCP tool-poisoning rules (`MCP007`–`MCP009`) also use — the same threat (a tool/skill description that manipulates the agent reading it) shows up in both surfaces.

Skill-bundle scanning deliberately inverts conventions that hold everywhere else in the codebase — see the "Evasion resistance" section of the [README](../README.md) and `src/scanner/deobfuscate.ts` / `src/scanner/skill-bundle.ts` for why (this is documented in depth in `CLAUDE.md` at the repo root; read that before touching either file).

### 4. Dependency advisories — offline, curated (`src/scanner/dependency-guard.ts`, `src/scanner/advisories.ts`)

`DEP001`–`DEP003` check every dependency (and every MCP-launched package) against a curated offline list. `DEP003` (documented malicious releases / critical CVEs) always runs; `DEP001`/`DEP002` (registry lookups, typosquat detection) are opt-in via `--check-dependencies` since they require network access. Version-range comparison goes through `src/scanner/semver.ts` — a finding only clears when a pinned version is provably outside the affected range, and stays flagged on anything ambiguous or unpinned.

## Pipeline after collection

```
Finding[] (from all 4 surfaces, merged + deduped)
  → evidence filter        (--paranoid: show heuristic tier too)
  → confidence filter      (--min-confidence)
  → severity filter        (-s/--severity)
  → baseline diff          (src/scanner/baseline.ts: new/changed findings only)
  → suppression comments   (// secureai-ignore RULE_ID: reason)
  → report                 (src/scanner/reporter.ts: terminal, sarif, json, markdown, html)
```

`src/scanner/scan.ts`'s `scanRepositoryDetailed` is the entry point that runs all four surfaces, merges, dedupes, and applies suppressions — this is the function every CLI command (`scan`, `bom`, `threat-model`) ultimately calls.

## The evidence-tier contract

This is the core design principle and is documented in full in [DetectionEngine.md](DetectionEngine.md). In short: every `Finding` carries a tier — `proven` (traced dataflow or a parsed config fact), `likely` (resolved sink + one heuristic hop), or `heuristic` (pattern/proximity only, hidden unless `--paranoid`) — and a bare keyword match is never enough on its own to reach `proven` or `likely`.

## Other entry points

- **`src/scanner/bom.ts`** — AI-BOM generation (`secureai-scan bom`), inventories SDKs/models/vector stores/MCP servers found across all four surfaces.
- **`src/scanner/threat-model.ts`** — generates `THREAT_MODEL.md` with an OWASP LLM/ASI/MCP coverage matrix, driven entirely off `src/scanner/catalog.ts`. Adding a rule to the catalog updates the matrix automatically.
- **`src/scanner/explainer.ts` + `src/scanner/catalog.ts`** — power `secureai-scan explain <RULE_ID>`.
- **`src/scanner/policy.ts`** — reads `.secureai-policy.json` (skip paths, blocked rules, min severity); `secureai-scan init` scaffolds one plus a GitHub Actions workflow.
- **`mcp-server/index.js`** — a standalone MCP server (plain Node, not compiled from `src/`) exposing `scan_repository`, `explain_rule`, `generate_bom`, `scan_untrusted_target` as MCP tools, so Claude (or any MCP client) can call the scanner directly.

## Why not one shared traversal?

It would be a natural-looking simplification to have one file-walking pass feed all rules. Two reasons this isn't done:

1. The TS/JS rules need a real AST (`ts-morph`) with type/import resolution; the Python, config, and skill-bundle surfaces are structurally different enough (text-based, JSON-based, whole-directory-based) that a shared traversal would need to be the lowest common denominator — plain file reads — which would force the AST rules to lose import resolution, the exact thing that keeps precision high.
2. Config and skill-bundle scanning intentionally skip the "usual" file filters (see `skill-bundle.ts`'s note on not using the shared skip-list) — folding them into a shared pass would risk accidentally reapplying those filters.

See `docs/Performance.md` for the cost of this (each surface does its own file discovery — a real, currently-unaddressed inefficiency, not a design requirement).
