# Threat Model

There are two documents named "threat model" in this repo and they answer different questions — this doc explains the difference and the methodology behind the second one.

- **`THREAT_MODEL.md`** (repo root) is *generated output* — run `secureai-scan threat-model .` and it produces a coverage matrix for *your* codebase against OWASP LLM/ASI/MCP Top 10, based on what SecureAI-Scan actually found. It's per-project and regenerates every time.
- **This document** is about SecureAI-Scan's own threat model: what classes of attack the tool is designed to catch, what it deliberately doesn't attempt, and why the boundary is drawn where it is.

## What's in scope

Detection scope is fixed to **LLM, MCP, and RAG/agent-related risk.** Concretely:

| Category | Rules | Representative real-world incident |
|---|---|---|
| Prompt injection (direct + indirect) | AI001, AI010 | User input or fetched content reaching a system prompt unsanitized |
| Sensitive data exposure to/from LLMs | AI002, AI004, AI008 | Secrets logged alongside prompts, whole objects serialized into prompts, credentials embedded in system prompt text |
| Unsafe output handling | AI005, AI012 | LLM output reaching `eval`/`exec`/SQL/HTML sinks unvalidated |
| Excessive agency | AI006, AI011 | High-impact tools (delete/pay/deploy) with no approval gate; agent output elevated to system-role downstream |
| Unbounded consumption | AI009 | Missing token/length limits on user input |
| MCP supply-chain and config risk | MCP002, MCP004–006, MCP010 | Unpinned `npx -y` servers, inline secrets in committed config, plaintext HTTP transport, command/args built from request data (the 2026 MCP STDIO RCE pattern) |
| MCP/Agent Skill tool poisoning | MCP001, MCP003, MCP007–009, SKL001–005 | Invisible Unicode, agent-directed injection phrases, and cross-tool shadowing in tool/skill descriptions — the pattern behind the WhatsApp MCP rug-pull and the postmark-mcp backdoor |
| RAG / vector-store weaknesses | AI007, VEC001–004 | Retrieved content interpolated into privileged prompts; vector search/ingestion without tenant isolation |
| Known-malicious/vulnerable dependencies | DEP001–003 | Documented backdoors and critical CVEs in AI-ecosystem packages, version-range aware |

## What's deliberately out of scope

**General-purpose SAST (SQL injection, XSS, path traversal unrelated to LLM/MCP context) and general secret-scanning are not goals of this tool**, even when a specific real incident would technically be caught by a broader rule. The postmark-mcp backdoor is the concrete case that tested this boundary directly: the payload was generic-looking business logic with nothing LLM-shaped about it. The correct response was adding it to the offline `DEP003` advisory list (name + version, a fact, not a pattern) — not writing a general-purpose heuristic that would also fire on ordinary, unrelated code far outside this tool's stated purpose. If your codebase needs SQLi/XSS/path-traversal coverage, run Semgrep or CodeQL alongside this tool — see the README's comparison table.

**Runtime/dynamic detection is out of scope.** Everything here is static analysis. `Cloak and Detonate` (arXiv:2607.02357) — the paper that motivated the evasion-resistance work in `deobfuscate.ts`/`skill-bundle.ts` — concludes correctly that runtime detonation beats static analysis against an adaptive adversary. What static scanning changes is the *cost* of evasion for currently-published techniques, not the theoretical ceiling. Treat an untrusted MCP server or Agent Skill as untrusted code regardless of what any static scanner says — this tool is a filter before you decide whether to run something, not a substitute for sandboxing it.

**Container, IaC, and dependency-CVE-in-general scanning are out of scope.** `DEP003` is narrowly AI-ecosystem-specific and curated by hand (public incident report or CVE required, per `CONTRIBUTING.md`) — it is not a general vulnerability database and shouldn't be treated as one.

## Framework mapping methodology

Every rule maps to the OWASP Top 10 for LLM Applications (2026) at minimum. Where the mapping is genuinely defensible (not forced), rules also map to the OWASP Top 10 for Agentic Applications (2026, ASI) and/or the OWASP MCP Top 10 (2025), and where relevant, an EU AI Act article. This mapping lives entirely in `src/scanner/catalog.ts`'s `RULE_CATALOG` and `FRAMEWORK_MAP` — adding a rule there is the only wiring needed for it to appear correctly in every generated `THREAT_MODEL.md`.

The mapping is not a claim that every sub-risk in an OWASP category is statically detectable. The [OWASP 2026 coverage document](OWASP2026.md) records the exact signals implemented today and the remaining static or runtime boundary.

The mapping is intentionally conservative: a rule is only mapped to an ASI or MCP Top 10 category if the fit is real, not because triple-framework coverage looks more impressive. `CATEGORY_LABELS` and `buildTrustBoundaries` in `threat-model.ts` need updating only if a genuinely new rule-ID prefix is introduced (a fifth scanning surface) — existing prefixes (AI/MCP/VEC/SKL/DEP) are already wired.
