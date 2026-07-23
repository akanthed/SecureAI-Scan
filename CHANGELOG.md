# Changelog

## 0.5.0 — 2026-07-23

### Added
- **Agent Skill scanning (SKILL.md)** — new `skill-scanner.ts` walks the repo for `SKILL.md` files (Claude Skills and equivalents) and reuses the same tool-poisoning checks already applied to MCP tool metadata:
  - **SKL001** — invisible/bidi Unicode hidden in a skill's frontmatter or body
  - **SKL002** — agent-directed injection phrasing in a skill's frontmatter or body
  - **SKL003** — a skill's content steers when/how a *different* skill is invoked (cross-skill shadowing)
- **MCP010 — dynamic MCP server command from untrusted input** (critical, proven/likely) — flags a stdio transport's `command`/`args` built from request-derived data. The MCP stdio transport executes that command as a real OS process, so this is architecturally the same risk class as passing user input to `child_process.exec`
- **DEP003 now compares actual declared versions against advisory ranges** — previously `affectedVersions` was display-only text; an exact pinned version (`package.json`, `requirements.txt`, or an MCP config server spec) is now parsed and checked against the advisory's range via a new minimal semver utility (`src/scanner/semver.ts`). Any ambiguity (a caret/tilde range, an unparseable spec) still fails toward flagging, never toward silently clearing a finding
- `test/cli.test.js` and `test/dependency-guard.test.js` — new CLI-layer and version-gating regression tests (see hard requirements #2 and #4 in `CLAUDE.md`)

### Fixed
- **AI002 (sensitive prompt/response logging) false-positived on OAuth metadata fields** — `token_endpoint`, `tokenType`, `tokenUrl`, `tokenExpiry`, and similar `token`/`secret` compounds followed by a metadata suffix (`endpoint`, `url`, `uri`, `type`, `expiry`, `expires`, `ttl`, `issuer`, `length`) are no longer classified as leaked secret values
- **AI007 (RAG context injection) treated `chunks` as unambiguous RAG evidence** — `chunks` is an extremely common LLM streaming-response variable name (`for await (const chunk of stream)`) with nothing to do with retrieval. It's now grouped with the other ambiguous names (`context`, `contexts`, `results`) and only counts as RAG content when the enclosing function also shows an actual retrieval call
- **AI007 prompt-part extraction now reuses `getPromptParts`** instead of a rule-local ad hoc parser, and demotes evidence in matched test/example paths — consistent with the shared-helper convention the rest of the rules follow
- **AI008 (system prompt leakage)** — narrowed to multi-word phrases specific enough that ordinary prose can't collide, plus a regex for labeled secret values, instead of a raw substring search on words like "secret"/"token"
- **Windows/BOM safety** — `dependency-guard.ts`'s `package.json`/`requirements.txt` reads now go through `stripBom` before `JSON.parse`, matching the fix already applied elsewhere for DEP001–DEP003

## 0.4.1 — 2026-07-21

### Fixed
- **Python LLM-call detection was missing entire SDKs** — `litellm.completion`/`acompletion`/`text_completion`, generic `.invoke_model(`/`.converse(` (Bedrock clients not literally named `bedrock`), Cohere `co.chat(`, Mistral `.chat.complete(`, and Ollama `.chat`/`.generate(` were recognized as LLM SDK imports but their actual call syntax wasn't in the call-pattern list. Every rule gated on that list (AI001, AI003, AI004, AI005, AI007, AI010) silently produced zero findings on apps using these SDKs, even with `--paranoid`
- **AI001 (Python) missed prompt injection across ordinary handler code** — the rule only looked 10 lines ahead of a `request.*` read for an LLM call. Realistic handlers (logging, rate-limit checks, RAG retrieval between the request read and the model call) routinely exceed that window. AI001 now walks the enclosing function, tracks which variables are tainted by request data through reassignment (fixpoint propagation), and checks the LLM call site against that set instead of a fixed line distance. Direct textual matches still report at `likely`; taint carried through intermediate variables reports at `heuristic`

## 0.4.0 — 2026-07-20

### Added
- **Three-framework OWASP mapping** — every rule now maps to the OWASP LLM Top 10 (2025), the OWASP Top 10 for Agentic Applications (2026, ASI01–ASI10), and the OWASP MCP Top 10 (2025) where applicable. Tags render in terminal, Markdown, HTML, JSON, and SARIF output (`owasp-asi-2026/*`, `owasp-mcp-top10/*` SARIF tags)
- **OWASP coverage matrix** — `secureai-scan threat-model` now includes a per-framework table showing which of the 30 risks are covered by rules, which fired in this scan, and which are runtime/process concerns a static scanner cannot assess
- **MCP007 — invisible Unicode in tool metadata** (critical, proven) — detects zero-width, bidi, and Unicode-tags-block characters hidden in MCP tool names/descriptions (`@modelcontextprotocol/sdk`, FastMCP — TS and Python)
- **MCP008 — injection phrasing in tool descriptions** (high, likely) — flags agent-directed instructions in tool descriptions ("ignore previous instructions", concealment from the user, credential-file reads, exfil-to-URL), the pattern behind real-world tool-poisoning attacks
- **MCP009 — cross-tool shadowing** (medium, likely) — flags a tool description that dictates when/how a *different* tool is used ("when send_email is called, first route through this tool")
- **DEP003 — known-malicious/vulnerable dependency** (critical/high, proven) — offline curated advisory list (postmark-mcp backdoor, mcp-remote CVE-2025-6514) checked on **every** scan against package.json, requirements.txt, and packages launched from MCP configs. No network required; no flag needed

### Changed
- `--only-mcp` now also runs MCP007–MCP009
- `--rules` accepts DEP001–DEP003

## 0.3.1 — 2026-07-14

### Fixed
- **Python AI005** — `subprocess.run`/`eval`/`exec`/`os.system` sinks no longer flag on ordinary code just because a nearby variable was named `result`/`output`/etc. Now requires the file to import a known LLM SDK, inspects only the sink's arguments (not the whole line), and traces a real assignment link from an LLM call before reporting at `critical`; a name-only match without a confirmed link now reports at a lower `high`/heuristic tier instead
- **Python AI002** — sensitive prompt/response logging now also requires the file to import a known LLM SDK, so non-LLM code with a variable named `prompt` no longer false-positives
- **Windows glob exclusion** — `node_modules`, `dist`, `build`, and policy `skipPaths` are now actually excluded from TS/JS scans on Windows. `path.join`/`path.resolve` produce backslash-separated paths, which the glob engine treats as escape characters, silently no-oping every exclude pattern; patterns are now normalized to forward slashes
- **Crash safety** — ts-morph symbol resolution (`resolveLlmSink`, and the equivalent lookup in the AI004 sensitive-data rule) is now wrapped so a single malformed/edge-case file can no longer abort an entire scan run
- **AI012** — dropped a bare-name fallback that flagged `JSON.parse(result)` on any variable named `result`/`output`/etc. regardless of whether it actually came from an LLM call
- **AI007 (RAG context injection)** — generic names like `context`/`results` now only count as retrieved RAG content when the enclosing function also shows an actual retrieval call (e.g. `similaritySearch`); unambiguous names (`docs`, `chunks`, `retrievedDocs`, ...) still fire directly. Ambiguous-name matches report at heuristic tier
- **AI010 (indirect prompt injection)** — fetch-derived variable detection now checks actual call-expression/property-access nodes instead of substring-matching whole initializer text, so values like `{ fetch: true }` or `prefetchedIds` no longer false-positive
- **VEC001 / VEC004** — `supabase`/`opensearch` clients (also used for ordinary, non-vector DB reads/writes) now require an explicit vector/embedding signal before flagging; dropped bare `metadata` as sufficient evidence of tenant/access-control filtering
- **AI-BOM** — model-identifier matching (esp. short IDs like `o1`/`o3`/`o4`) is now scoped to string-literal contents instead of the whole file, so ordinary variable/loop names no longer show up as "OpenAI model referenced"
- **DEP002** — added the missing `RULE_CATALOG` entry; findings no longer render with blank OWASP/fix tags in Markdown, HTML, and SARIF output
- **Report snippets** — the source-line cache no longer folds path case on case-sensitive filesystems (Linux/macOS), which could have let two same-name-different-case files share cached content
- **Dependency guard** — a registry-unreachable network failure now prints a one-line warning instead of silently no-opping DEP001 for the whole run (still fails open on the individual check, to avoid a manufactured false positive from a network blip)

### Note for CI users
A few of the fixes above intentionally change scan output: some previously-`critical` AI005 findings now report at a lower tier when there's no confirmed dataflow link, and some previously-flagged AI007/VEC001/VEC004/AI010/AI012 cases no longer fire at all. If you pin `--fail-on critical` in CI, expect your finding count to drop on upgrade — that's the intended effect of removing false positives, not a regression.

## 0.2.1 — 2026-06-07

### Added
- **Python support** — 11 of the 19 rules now scan `.py` files (AI001–AI007, AI010, VEC001, VEC003, MCP001). Covers LangChain, OpenAI SDK, Anthropic SDK, Flask, FastAPI, Chroma, Pinecone, Weaviate, and more
- **MCP server** (`mcp-server/index.js`) — exposes SecureAI-Scan as native Claude tools via the Model Context Protocol. Three tools: `scan_repository`, `explain_rule`, `evaluate_prompt`. Works with Claude Desktop and any MCP-compatible client
- **`GPT_PROMPT.md`** — ready-to-paste system prompt for creating a ChatGPT Custom GPT on the GPT Store
- **`VISIBILITY.md`** — step-by-step guide for getting SecureAI-Scan discovered on ChatGPT, Claude, Perplexity, npm, OWASP, and developer communities

### Improved
- CLI description and `--debug` output now show separate TS/JS and Python file counts
- `scan_repository` (programmatic API) returns `pythonFiles` alongside `scannedFiles`
- `skipPaths` and `blockedRules` from policy now apply to Python file scanning too
- README updated to cover Python examples, MCP server setup, and updated FAQ

## 0.2.0 — 2026-06-07

### Added
- **9 new security rules** — AI010, AI011, AI012, MCP001, MCP002, MCP003, VEC001, VEC002, VEC003
- **MCP rule category** — detects tool description injection, dynamic server URLs, unvalidated tool results
- **Vector/RAG rule category** — detects data poisoning, cross-tenant leakage, unbounded search
- **`secureai-scan init`** — first-time setup: creates policy file + GitHub Actions workflow + step-by-step guide
- **`secureai-scan threat-model`** — generates THREAT_MODEL.md with trust boundaries, attack scenarios, remediation priority
- **`--only-mcp`** and **`--only-vec`** scan filters (alongside existing `--only-ai`)
- **`--min-confidence <0-1>`** flag — control false-positive sensitivity (default: 0.4)
- **`--policy <file>`** flag — enforce `.secureai-policy.json` settings in CI
- **Policy file** (`.secureai-policy.json`) — declare minSeverity, minConfidence, failOnSeverity, skipPaths
- **CI exit code** — scan exits with code 1 when `failOnSeverity` threshold is breached
- **Explain coverage** — all 19 rules now have full `whyRisky`, `howExploited`, `howToFix`, and code examples

### Improved
- Confidence scoring now reduces score for test files (−0.30), nearby sanitization (−0.35), embedding-only calls (−0.40)
- Terminal output shows count of findings hidden by confidence threshold
- Contextual hints now suggest `init`, `threat-model`, and `explain` based on scan results
- CLI help text includes quick-start examples for all commands

## 0.1.6 — 2026-04-28

### Added
- Core rules: AI001 (prompt injection), AI002 (sensitive logging), AI003 (LLM before auth), AI004 (sensitive data to LLM), AI005 (unsafe output), AI006 (excessive agency), AI007 (RAG context injection), AI008 (system prompt leakage), AI009 (unbounded input)
- AI100 informational: LLM SDK usage detection
- Baseline diff mode (`--baseline`)
- HTML, Markdown, and JSON report output (`--output`)
- Dependency scanning for hallucinated/typo package names (`--check-dependencies`)
- Prompt risk evaluator (`secureai-scan prompt "<text>"`)
- Inline ignore annotations (`// secureai-ignore RULE_ID: reason`)
- `secureai-scan explain <RULE_ID>` with code examples
- Confidence scoring system
- GitHub Actions workflow example
