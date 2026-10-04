# Testing & benchmarking

Three layers, because one alone isn't enough to trust a scanner's claims — precision and recall are different failure modes, and both get checked.

**1. Fixture corpus — precision + recall, runs on every build.**

```bash
npm test
```

[`test-fixtures/vulnerable/`](../test-fixtures/vulnerable) and [`test-fixtures/safe/`](../test-fixtures/safe) are scanned together: every vulnerable fixture must fire its expected rule at `proven`/`likely` evidence (recall), every safe fixture must produce **zero** `proven`/`likely` findings (precision). Fast and deterministic — but it only proves the scanner behaves on code written specifically to test it.

**2. Real-world regression benchmark — against public repos we didn't write.**

```bash
npm run regression                          # scan the full curated repo set
npm run regression -- --fresh               # re-clone everything first
npm run regression -- openai-node           # scan just one repo by name
npm run regression -- --update-baseline     # accept the current findings
```

[`scripts/regression-scan.js`](../scripts/regression-scan.js) clones a curated, diverse set of real public repos (OpenAI/Anthropic/Vercel AI SDKs, the official MCP servers and TypeScript SDK, LlamaIndex, plus [anthropics/skills](https://github.com/anthropics/skills) and [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) for skill-bundle coverage — spanning TS and Python, SDK-consumer example code and SDK-author source) and scans each with the built CLI.

It **exits non-zero on any `proven`/`likely` finding not already in [`test/regression-baseline.json`](../test/regression-baseline.json)** — a hand-reviewed record of findings already read against their source line. Fingerprints are `repo|rule|file`, not line numbers, so ordinary upstream churn doesn't produce noise. A new fingerprint is a claim the scanner has to justify: if it isn't a genuine issue it's a rule bug, fixed at the root cause and locked in as a new `test-fixtures/safe/` fixture. Baselining a finding you haven't read defeats the entire mechanism.

**Skill-bundle coverage gets its own line** because `cisco-ai-defense/skill-scanner`'s `evals/` corpus is labeled — each of its 20 fixtures ships an `_expected.json` verdict and sits under a directory literally named `malicious/` or `safe/`, so it doubles as a recall check, not just a precision one: **6/6 in-scope malicious fixtures fire, 0 findings on anything labeled safe**, and 0 findings across all 18 real bundles in `anthropics/skills` and all 14 in `vercel/ai`. (The remaining Cisco categories — SQL injection, path traversal, resource exhaustion, generic `eval()` of a function argument, a payload deliberately split across four files — are either out of the documented LLM/MCP/RAG scope or beyond same-file conjunction analysis; see the [0.6.0 changelog entry](../CHANGELOG.md) for the specific reasoning on each.)

Historical before/after from the run that drove the original precision fixes (findings at default evidence level, no `--paranoid`):

| Repo | Before | After | What was wrong |
|------|-------:|------:|-----------------|
| [vercel/ai](https://github.com/vercel/ai) | 773 | 1 | `examples/`, top-level `tests/`, and hyphenated `ecosystem-tests/`-style directories weren't recognized as lower-trust paths; `chunks` (a common streaming-response variable) was treated as unambiguous RAG evidence |
| [openai/openai-node](https://github.com/openai/openai-node) | 47 | 0 | Same path-detection gap, applied to the SDK's own `examples/`/`ecosystem-tests/` |
| [anthropics/anthropic-sdk-typescript](https://github.com/anthropics/anthropic-sdk-typescript) | 2 | 0 | Same path-detection gap on a top-level `tests/` directory |
| [modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk) | 3 | 0 | `token_endpoint`/`tokenType`-style OAuth metadata fields flagged as leaked secrets |
| [run-llama/llama_index](https://github.com/run-llama/llama_index) | 18 | 15 | A Python check flagged any `description=` field containing "system prompt" as `proven` MCP tool poisoning, regardless of context. The remaining 15 are `VEC001` hits on the library's own generic retriever definitions — scanning a vector-DB SDK's own source, not application code, so a filter can't exist to check; an honest, inherent limit, not a bug |

**Current run (2026-08-06)** — versioned evidence is recorded in [`docs/benchmarks/v0.9.0.json`](benchmarks/v0.9.0.json):

| Repo | Findings | Rules | Status |
|------|---------:|-------|--------|
| openai-node, anthropic-sdk-typescript, anthropic-sdk-python, modelcontextprotocol/typescript-sdk, modelcontextprotocol/servers | 0 | — | clean |
| [anthropics/skills](https://github.com/anthropics/skills) (18 real skill bundles) | 0 | — | clean — pure precision check for SKL001–005 |
| [vercel/ai](https://github.com/vercel/ai) (5,691 files) | 0 | — | **was 40** (AI001, AI003, AI005, AI010, MCP002) before triage — every one hand-reviewed against source and confirmed a false positive, traced to 3 independent root-cause bugs (see below), fixed, and re-confirmed clean on a full re-scan |
| [run-llama/llama_index](https://github.com/run-llama/llama_index) | 46 | VEC001 | inherent limit, not a bug — the library's own generic retriever definitions, where no tenant filter can exist to find |
| [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) | 7 | SKL001, SKL002, SKL005 | **all on fixtures labeled `malicious/`** — 6/6 in-scope, 0 on anything labeled `safe/` |

The `vercel/ai` triage found three real, root-caused bugs — none specific to the v0.6.0 skill rules, all in shared logic used across many rules:

1. **`resolveLlmSink` treated any call resolved to an LLM SDK module as a model invocation, regardless of method name** — flagging `isToolUIPart` (a type guard the `ai` package exports right alongside `generateText`) as an LLM call. This alone caused 3 of the 5 finding groups (AI001, AI003, AI010).
2. **`DANGEROUS_CALLEES` in AI005 includes `"query"` for SQL-injection-style sinks, but `"query"` is also a legitimate LLM/agent invocation verb** — `claudeSdk.query({ prompt, options })`, the Claude Agent SDK's own model call, was flagged as "LLM output passed to a dangerous sink" purely because of the shared method name.
3. **`REQUEST_SOURCES` (duplicated identically across MCP002, MCP010, VEC003) matched a bare `"params."`** — any function parameter conventionally named `params`, not necessarily HTTP request data. A URL-scheme validator (`assertOpenLinkParams(params: unknown)`) got flagged as "MCP server URL from user input."

All three fixed at the root cause (not the specific call site) and pinned as permanent fixtures under `test-fixtures/`. Full details in `CHANGELOG.md`.

**3. Vulnerable-vs-patched validation — proves recall, not just precision.**

The two layers above only check that the scanner stays quiet on safe code. `DEP003`'s advisory checks are validated the other way: pin a package to a documented-vulnerable version and confirm it's flagged, then pin it to the patched version and confirm it isn't.

```bash
node --test test/dependency-guard.test.js
```

covers: `mcp-remote@0.1.15` (CVE-2025-6514, vulnerable) flagged / `mcp-remote@0.1.16` (patched) clear; `postmark-mcp@1.0.15` (before the backdoor) clear / `postmark-mcp@1.0.20` (after — no legitimate patch exists for a malicious package) still flagged; `llama-cpp-python==0.2.71` (CVE-2024-34359, from the OSV-generated set) flagged / `==0.2.72` (patched) clear, including under PyPI name normalization (`llama_cpp_python`); and `langchain>=0.1.0`-style unpinned specifiers producing **zero** default-report findings. Building this test caught a real gap: `DEP003` used to match advisories by package name only, never actually comparing the declared version against the advisory's affected range — fixed in [`src/scanner/semver.ts`](../src/scanner/semver.ts).

Ambiguity is resolved differently per advisory kind, deliberately. A **malicious** package fires even when the declared version can't be resolved — installing a backdoor is unrecoverable, so it fails toward flagging. A **CVE** fires at `proven` only when the declared version is an exact pin provably inside the affected range; unpinned-but-possibly-affected drops to `heuristic` (`--paranoid` only). Applying the malicious-kind rule to a 162-entry CVE snapshot would put a critical finding on every repo that declares `langchain>=0.1.0` — unactionable noise at scale.

**4. Published-CVE recall — real vulnerabilities, scanned before and after the fix.**

`MCP013`/`MCP014` are checked against every MCP server we could find with a published command-injection advisory: the last vulnerable commit must fire, and the fix commit must be clean. Current result: **6/6 detected, 6/6 clean after the patch** (CVE-2025-53967, CVE-2025-53355, CVE-2025-54073, CVE-2025-53818, CVE-2025-53372, CVE-2025-52573), plus no default-tier MCP013/MCP014 findings across 25 popular MCP servers without a CVE. The table, the exact commits, and what each miss taught us are in [What we found scanning real repos](RealWorldFindings.md#we-pointed-it-at-six-mcp-servers-with-published-command-injection-cves). The structural shapes behind those CVEs (dispatcher → handler in another file → imported `promisify(exec)`; tool registry → class-method chain → conditional command) are reproduced as fixtures in [`test-fixtures/vulnerable/mcp-tool-sinks/`](../test-fixtures/vulnerable/mcp-tool-sinks), so `npm test` keeps them caught.
