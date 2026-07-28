# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`secureai-scan` (npm) — a static AI/LLM security scanner for TypeScript, JavaScript, and Python. It finds prompt injection, MCP supply-chain risks, RAG poisoning, Agent Skill poisoning, and related OWASP LLM/ASI/MCP Top 10 issues, and proves findings with source→flow→sink dataflow traces rather than keyword matching alone.

## Hard requirements (non-negotiable, apply to every change)

### 1. Zero tolerance for false positives

This is the product's entire value proposition (see the "precision contract" in README.md) — a scanner nobody trusts because it cries wolf is worse than no scanner. Any change to detection logic (a rule file, `tool-poisoning-checks.ts`, `python-scanner.ts`, `confidence.ts`, etc.) must not introduce new false positives, and existing false positives found during work should be fixed, not worked around.

- The internal precision gate (`test-fixtures/safe/` + `test/corpus.test.js`) enforces zero `proven`/`likely` findings on known-safe patterns — this must stay green, and any bug fixed for a false positive gets a permanent fixture there so it can't regress silently.
- That corpus alone is not sufficient — it only proves the scanner behaves on code we wrote to test it. See the regression-scan requirement below for the check that catches what it can't.
- When you find a false positive, fix the root cause (a rule's evidence tier, an unguarded keyword match, a missing `isTestFilePath` demotion, an overly broad name set) rather than special-casing the one input that revealed it.

### 2. Test against real-world repos, not just fixtures, before calling detection work done

For any change that touches detection logic (new rule, edited rule, edited shared matcher), run:

```bash
npm run regression
```

This clones a curated set of real public repos (`scripts/regression-scan.js` — OpenAI/Anthropic/Vercel AI SDKs, official MCP servers and SDK, LlamaIndex) into `.regression-cache/` (gitignored, cached across runs — pass `--fresh` to re-clone, or a repo name to scan just one) and scans each with the built CLI. It is not a pass/fail gate — there's no fixed expected count, since upstream repos change. Read every `proven`/`likely` finding it prints against its source line:

- If it's a real issue in that repo, that's expected — leave it.
- If it isn't, it's a bug in a rule. Fix the rule, then add the offending pattern as a new fixture under `test-fixtures/safe/` (with a comment noting which repo/file it came from) so `npm test` locks in the fix permanently.

This is how several real false-positive classes were found and fixed in this codebase: `token_endpoint`/`tokenType` fields flagged as leaked secrets (AI002 matched "token" as a bare identifier token with no regard for context), example/demo/`ecosystem-tests`-style directories not being recognized as lower-trust paths (`isTestFilePath` only matched a narrow set of literal `/test/`/`/tests/` segments), `chunks` (an extremely common LLM streaming-response variable name) being treated as unambiguous RAG evidence (AI007), narrative/fiction prompt text containing the bare English words "secret"/"token" being flagged as leaked credentials (AI008 did a raw substring search with no requirement that the match look like an actual credential value), and a Python MCP001 check that flagged *any* `description=` field containing phrases like "system prompt" with `proven` evidence regardless of whether the file had anything to do with MCP at all. Consider that class of bug — a keyword/substring match applied without enough surrounding context, given undeservedly high evidence — the default failure mode to watch for.

### 3. Recall/true-positive validation matters as much as precision — and stay scoped to LLM/MCP/RAG

Zero false positives is necessary but not sufficient — a scanner that's quiet by default but also blind is worse, and silence reads as "all clear." When a curated advisory (`DEP003`) claims to gate on a version range, prove it both ways: pin a package to the documented-vulnerable version and confirm it fires, then pin it to the patched version and confirm it clears (`test/dependency-guard.test.js` does this for CVE-2025-6514). This exact exercise caught a real bug — `affectedVersions` was display-only text, never actually compared against the declared version — and, separately, a UTF-8 BOM in `package.json` silently zeroing out `DEP001`–`003` via a swallowed `JSON.parse` error (fixed with `src/utils/text.ts`'s `stripBom`, applied at every JSON-config read site).

That said, **detection scope is fixed to LLM/MCP/RAG-related risks.** When a real incident (e.g. the postmark-mcp backdoor) turns out to be undetectable by any in-scope pattern rule — because the payload is generic-looking business logic with nothing LLM-shaped about it — the correct fix is the offline advisory list (name+version), or an honest documented gap. Do not propose or add general-purpose SAST/secret-scanning heuristics to close a gap like that; a rule broad enough to catch it would fire constantly on ordinary, unrelated code.

### 4. The CLI layer needs its own tests — detection-logic tests don't cover it

Every test file except `test/cli.test.js` calls scanner functions directly, bypassing `src/cli.ts` entirely. A bug in flag wiring (a dropped custom-parser argument, a flag that silently no-ops without a second required flag) has no other test that would catch it — this happened once already (a regrouping edit to `scan`'s options accidentally dropped `-r/--rules`'s parser function; `npm test` stayed green because nothing exercised the built binary). Any change to `src/cli.ts` — new flag, reordered options, changed wiring between flags — needs a corresponding case in `test/cli.test.js`, which runs the real built binary via `execFileSync`, not the underlying functions.

## Commands

```bash
npm run build      # clean + tsc compile to dist/
npm run dev         # build + run dist/index.js
npm test             # build, then run test/run-tests.js (node:test, no separate runner)
npm run regression   # build, then real-world repo scan (see above)
node --test test/corpus.test.js   # run a single test file directly (after building)
```

There is no separate lint script — `tsc` (strict mode, see `tsconfig.json`) is the only static check. Always `npm run build` before running tests: tests import from `dist/`, not `src/`.

### Running the CLI locally

```bash
node dist/index.js scan <path>
node dist/index.js scan . --paranoid --output report.sarif
node dist/index.js explain AI001
node dist/index.js bom .
```

## Architecture

### Three independent scanning surfaces, merged into one output

- **TS/JS**: AST-based via `ts-morph` (`src/scanner/project.ts` builds the `Project`; rules in `src/scanner/rules/*.ts` walk the AST).
- **Python**: regex-pattern based, not AST (`src/scanner/python-scanner.ts`). Patterns for LLM SDK calls, request-input taint sources, vector store calls, and exec sinks are matched line-by-line with a small taint-propagation pass. Being regex-based, it's more prone to context-free matches than the AST rules — see the MCP001 false-positive class above.
- **Config/content files scanned off disk directly** (not via the ts-morph `Project`): `src/scanner/mcp-config-scanner.ts` (`.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json` → `MCP004`–`MCP006`) and `src/scanner/skill-scanner.ts` (Agent Skill bundles → `SKL001`–`SKL005`, reusing the same invisible-Unicode/injection-phrase/cross-reference checks in `tool-poisoning-checks.ts` that the MCP tool-poisoning rules use).
- **Dependency advisories** (`DEP001`–`DEP003`) run out of `src/scanner/dependency-guard.ts` against a curated offline list in `src/scanner/advisories.ts`. DEP003 (documented malicious/CVE packages) always runs; DEP001/DEP002 (registry lookups, typosquat detection) are opt-in via `--check-dependencies` since they need network access.

`src/scanner/scan.ts` (`scanRepositoryDetailed`) is the entry point that runs all of the above, merges findings, dedupes, and applies `// secureai-ignore RULE_ID: reason` suppression comments.

### Rule shape

Every AST rule lives in `src/scanner/rules/` and exports a `Rule` object (`id`, `title`, `severity`, `run(context)`). New rules must be registered in `src/scanner/rules/index.ts`'s `RULES` array (or the adjacent `CONFIG_RULE_IDS`/`SKILL_RULE_IDS`/`DEPENDENCY_RULE_IDS` for the non-AST scanners) — this is also the source of truth for `AVAILABLE_RULE_IDS`.

Shared helpers: `src/scanner/rules/llm-rule-utils.ts` (resolves whether a call is a real LLM SDK sink via import resolution, extracts prompt message parts *with role* via `getPromptParts` — always prefer this over writing a new ad hoc prompt-part extractor, since a rule-specific reimplementation is exactly what caused the AI007 false-positive class) and `src/utils/ast.ts` (node/line helpers, string-concat detection).

### Evasion resistance (skill bundles)

Two modules exist specifically to defeat the published scanner-evasion techniques in *Cloak and Detonate* (arXiv:2607.02357) and the Gecko Security test-file vector. Both invert conventions that hold everywhere else in this codebase, deliberately:

- **`src/scanner/deobfuscate.ts`** — content checks match against normalized *variants* (invisible-stripped, homoglyph-folded, string-splice-joined, intra-word-break-joined) instead of one byte sequence. `matchAcrossVariants` compares against the *set* of raw hits, not "did the raw text match at all" — otherwise an attacker masks the evasion signal by leaving one benign phrase in the clear. **A hit found only after deobfuscation is promoted to `proven`, not demoted**: prose does not contain a zero-width joiner inside "ignore previous instructions". This is the one place where a heuristic transform *raises* evidence, and it is justified because the concealment is the evidence.
- **`src/scanner/skill-bundle.ts`** — walks a skill's whole directory, ignoring the skip-lists used elsewhere (`build/`, `docs/`, `.git/`, renamed extensions, oversized files are head-read not skipped). Inside a bundle's `.git/`, any file that is not a git internal (see `GIT_INTERNAL_ENTRIES`) is `proven`-tier on its own — nothing else writes there. **SKL005 deliberately does not call `isTestFilePath`**: a payload in `*.test.ts` is the published attack precisely because every other scanner demotes or skips it, and test runners auto-execute those files. Do not "fix" that by adding the demotion back.

Because a bundle can be an entire repository (when `SKILL.md` sits at a repo root), both bundle rules require a *linked* conjunction rather than co-occurrence: SKL004's unpack directive must name the blob, and SKL005's credential read and egress must be within `EXFIL_PROXIMITY_LINES` of each other in the same file. Loosening either is how these rules would start firing on ordinary monorepos.

### The evidence-tier contract (this is the core design principle)

Every `Finding` carries an `Evidence` tier (`src/scanner/types.ts`):
- `proven` — import-resolved sink + traced dataflow, or a parsed config fact.
- `likely` — resolved sink or strong structural signal, with one heuristic hop.
- `heuristic` — pattern/proximity match only, hidden unless `--paranoid`.

Rules only flag an "LLM call" if the callee resolves through actual imports to a known SDK (`resolveLlmSink` in `llm-rule-utils.ts`) — never by name-matching alone. `src/scanner/confidence.ts` provides `evidenceConfidence()` (maps tier → numeric score), `demoteEvidence()` (downgrade one tier — test files, weaker taint origins, etc.), and `isTestFilePath()` (matches test/example/demo/fixture path *segments*, not raw substrings — a file under `examples/`, top-level `tests/`, or a hyphenated dir like `ecosystem-tests/` all count; this was itself a false-positive source before its segment-based rewrite). New rules touching request/user-controlled data should call `isTestFilePath` and demote evidence in matched test/example paths, matching the convention in `prompt-injection-concat.ts`, `llm-before-auth.ts`, `mcp-dynamic-server-url.ts`, etc. — a rule that skips this (as AI007/AI008 originally did) is a latent false-positive source in any repo that ships example code, which is most of them.

A bare keyword/substring match with no surrounding context is never enough to justify `proven` or even `likely` — require either a traced dataflow, an import-resolved sink, or (for text-content rules like AI008/MCP008/SKL002) a value/phrase shape specific enough that ordinary prose or unrelated identifiers can't collide with it.

### The precision gate (test corpus)

`test-fixtures/vulnerable/` and `test-fixtures/safe/` are the regression corpus enforced by `test/corpus.test.js`:
- Every fixture in `vulnerable/` must fire its expected rule at `proven` or `likely` evidence (see the `EXPECTED_VULNERABLE` list in that test).
- Every fixture in `safe/` must produce **zero** `proven`/`likely` findings — these are patterns that previously caused false positives (redacted PII, ordinary logging, env-var API keys near LLM clients, non-LLM clients that merely look like one, OAuth metadata fields, streaming-response `chunks`, fiction/narrative prompt text, framework config fields).

Any change to a rule's detection logic must be checked against this corpus, **and** against `npm run regression` per the hard requirement above. If a rule needs new coverage, add a fixture to both directories as appropriate.

### Findings pipeline (after collection)

`Finding[]` → evidence filter (`--paranoid`) → confidence filter (`--min-confidence`) → severity filter → baseline diff (`src/scanner/baseline.ts`, tracks new/changed only) → report (`src/scanner/reporter.ts`, formats: terminal, `sarif`, `json`, `markdown`, `html`).

### Other entry points

- `src/scanner/bom.ts` — AI-BOM generation (`secureai-scan bom`), inventories SDKs/models/vector stores/MCP servers.
- `src/scanner/threat-model.ts` — generates `THREAT_MODEL.md` with an OWASP LLM/ASI/MCP coverage matrix, driven entirely off `src/scanner/catalog.ts`'s `RULE_CATALOG`/`FRAMEWORK_MAP` (add a rule there and the matrix updates itself — no separate wiring needed except `CATEGORY_LABELS`/`buildTrustBoundaries` for a genuinely new rule-ID prefix).
- `src/scanner/explainer.ts` + `src/scanner/catalog.ts` — power `secureai-scan explain <RULE_ID>` (static per-rule why/exploit/fix content keyed by rule ID). **Every new rule needs an entry in both** — `explainer.ts` silently falls back to generic boilerplate for unregistered IDs, which is easy to miss since nothing fails a build or test over it.
- `src/scanner/policy.ts` — reads `.secureai-policy.json` (skip paths, blocked rules, min severity) and scaffolds it + a GitHub Actions workflow via `secureai-scan init`.
- `mcp-server/index.js` — standalone MCP server (plain Node, not TS) exposing `scan_repository`, `explain_rule`, `generate_bom` as MCP tools; ships as-is in the npm package (`files` in `package.json`), not compiled from `src/`.

## Adding a new rule

1. Add `src/scanner/rules/<name>.ts` exporting a `Rule`. Use `resolveLlmSink`/`getPromptParts` from `llm-rule-utils.ts` for anything touching an LLM call, call `isTestFilePath` and demote evidence in matched paths, and pick evidence tiers deliberately (see above).
2. Register it in the `RULES` array in `src/scanner/rules/index.ts`.
3. Add a catalog entry in `src/scanner/catalog.ts` (title/owasp/impact/fix, plus `FRAMEWORK_MAP` if an ASI/MCP-Top10 mapping is defensible) **and** an entry in `src/scanner/explainer.ts`'s `DEFAULT_EXPLANATIONS` — both are easy to forget since nothing enforces them.
4. Add a vulnerable fixture (must fire) and, if there's a plausible false-positive shape, a safe fixture (must stay clean) under `test-fixtures/`, then extend `EXPECTED_VULNERABLE` in `test/corpus.test.js`.
5. `npm run build && npm test`, then `npm run regression` before considering the rule done.

## Package advisories (DEP003)

`src/scanner/advisories.ts` feeds `proven`-tier findings, so the bar for additions is strict (see `CONTRIBUTING.md`): only packages with a public incident report or CVE, with version ranges when documented, and a corresponding case added to `test/dependency-guard.test.js`. Don't add an advisory for an incident where the exact package name/ecosystem isn't publicly documented — a plausible guess is not the same as a citable fact.
