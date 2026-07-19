# Changelog

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
