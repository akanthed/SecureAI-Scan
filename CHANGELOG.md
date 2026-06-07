# Changelog

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
