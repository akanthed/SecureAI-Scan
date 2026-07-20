# SecureAI-Scan

[![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-supported-yellow.svg)](https://www.python.org/)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![ChatGPT](https://img.shields.io/badge/ChatGPT-GPT%20available-74aa9c?logo=openai&logoColor=white)](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20%C2%B7%20ASI%20%C2%B7%20MCP%20Top%2010-000000)](#rules)

**The AI security scanner that proves its findings.**

SecureAI-Scan finds LLM, MCP, and RAG vulnerabilities in **TypeScript, JavaScript, and Python** — and shows you the evidence: the exact source → flow → sink path for every dataflow finding, resolved through real imports, not keyword matching.

As of v0.4.0, it's the first scanner mapped to **all three** OWASP AI security frameworks — the LLM Top 10, the [Top 10 for Agentic Applications (2026)](https://genai.owasp.org/), and the [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) — with a coverage matrix in every threat model showing exactly which risks are checked and which are runtime concerns.

```
  ▌ HIGH  AI001  Prompt injection via user input
    PROVEN  LLM01 Prompt Injection

    source src/chat.ts:8   request data `req.body.input`
    flow   src/chat.ts:13  passed as `systemPrompt`
    sink   src/chat.ts:10  openai.chat.completions.create — system role (OpenAI)

    fix    Keep system prompts static; pass user input as a user-role message.
```

## Why this scanner is different

- **Evidence tiers, not noise.** Every finding is `proven` (traced dataflow or parsed config fact), `likely` (resolved sink, one heuristic hop), or `heuristic`. **A default scan shows only proven + likely.** Heuristics are opt-in via `--paranoid`.
- **Import-resolved detection.** A call is only an "LLM call" if it resolves to a real SDK import (`openai`, `@anthropic-ai/sdk`, `ai`, `@google/genai`, LangChain, Bedrock, …). Your Google Maps client will never be flagged as an LLM again.
- **Precision-gated in CI.** The test suite asserts every vulnerable fixture fires *and* every safe fixture stays clean. A false positive on the safe corpus fails the build.
- **SARIF for GitHub code scanning.** `--output report.sarif` puts findings inline on pull requests and in the Security tab.
- **AI-BOM.** `secureai-scan bom .` inventories every SDK, model ID, vector store, agent framework, and MCP server in your repo — zero-false-positive by construction, mapped to OWASP LLM Top 10 / EU AI Act documentation needs.
- **MCP config scanning.** Parses `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`: unpinned `npx -y` servers, inline secrets, plaintext HTTP transports.
- **MCP tool-poisoning detection.** Catches the pattern behind the WhatsApp MCP rug-pull and postmark-mcp backdoor — invisible Unicode, agent-directed injection phrases, and cross-tool shadowing in tool names/descriptions, statically, before you ever run the server.
- **Known-malicious package advisories.** Checks every dependency and every MCP-launched package against a curated advisory list (documented backdoors, critical CVEs) — offline, on every scan, no flag required.
- **Local-first.** Nothing leaves your machine.

## Get started in 30 seconds

```bash
npx --yes secureai-scan@latest scan .
```

TypeScript, JavaScript, Python, and MCP config files are scanned automatically.

> Prefer to ask questions first? Try the free **[SecureAI-Scan AI Security Advisor on ChatGPT](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)**.

> About to run an MCP server you found on GitHub or Twitter? Paste its tool description into **[MCP X-Ray](https://akanthed.github.io/SecureAI-Scan/)** first — checks it for hidden Unicode, injected instructions, and known-malicious packages in your browser, no install.

## Commands

```bash
secureai-scan scan .                     # proven + likely findings
secureai-scan scan . --paranoid          # include heuristic tier
secureai-scan scan . --output r.sarif    # GitHub code scanning (also .html/.md/.json)
secureai-scan scan . --fail-on high      # CI gate: exit 1 at/above severity
secureai-scan scan . --baseline .secureai-baseline.json   # only new issues
secureai-scan bom . --output AI_BOM.md   # AI Bill of Materials
secureai-scan explain AI001              # why + exploit + fix example
secureai-scan threat-model .             # THREAT_MODEL.md for review
secureai-scan init                       # policy file + CI workflow
```

Suppress a reviewed finding in code:

```ts
// secureai-ignore AI001: reviewed, input sanitized via allowlist
```

## GitHub Action

```yaml
name: SecureAI-Scan
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: akanthed/SecureAI-Scan@main
        with:
          fail-on: high
```

Findings appear as inline annotations on the PR and in the repository's Security tab. (`secureai-scan init` generates an equivalent workflow using the CLI directly.)

Scanning clean? Add the badge to your own README:

```md
[![secureai-scan](https://img.shields.io/badge/secureai--scan-passing-brightgreen)](https://github.com/akanthed/SecureAI-Scan)
```

## Rules

Every rule maps to the OWASP LLM Top 10 (2025) — plus, where applicable, the OWASP Top 10 for Agentic Applications (2026, ASI) and the OWASP MCP Top 10 (2025) — and, where relevant, an EU AI Act article. `threat-model` output includes a full coverage matrix across all three frameworks.

| Rule | What it proves | OWASP |
|------|----------------|-------|
| AI001 | User input flows into a system/developer prompt (traced source → sink) | LLM01 |
| AI002 | Prompt content or secrets written to logs (in files that use an LLM SDK) | LLM02 |
| AI003 | LLM call in a request handler with no auth check before it | LLM10 |
| AI004 | Whole user/session object serialized into a prompt (field-picking is not flagged) | LLM02 |
| AI005 | LLM output reaches eval/exec/SQL/HTML sinks | LLM05 |
| AI006 | High-impact tools (delete, pay, deploy, …) exposed without an approval gate | LLM06 |
| AI007 | Retrieved RAG content interpolated into privileged prompts | LLM01 |
| AI008 | Secrets embedded in system prompt text | LLM07 |
| AI009 | Unbounded user input / missing token limits | LLM10 |
| AI010 | Fetched external content flows into prompts | LLM01 |
| AI011 | Agent output elevated to system-role in downstream calls | LLM06 |
| AI012 | LLM output parsed without schema validation | LLM05 |
| MCP001 | MCP tool metadata reaches the system prompt without validation | LLM01 |
| MCP002 | MCP server URL constructed from user input | LLM03 |
| MCP003 | MCP tool results elevated to system-role | LLM05 |
| MCP004 | MCP server launched as an unpinned `npx -y` package | LLM03 |
| MCP005 | Secret inlined in a committed MCP config | LLM02 |
| MCP006 | MCP server over plaintext HTTP | LLM03 |
| MCP007 | Invisible/bidi Unicode hidden in MCP tool names or descriptions | LLM01 · MCP03 |
| MCP008 | Agent-directed injection phrases in MCP tool descriptions | LLM01 · MCP03 |
| MCP009 | A tool description that steers calls to a different tool (shadowing) | LLM01 · MCP03 |
| VEC001 | Vector search without a tenant/user filter | LLM08 |
| VEC002 | Unbounded or user-controlled search limit | LLM10 |
| VEC003 | User content ingested into a shared vector store | LLM04 |
| VEC004 | Ingestion without tenant/namespace tagging | LLM08 |
| DEP001 | Dependency name not found in the registry (opt-in `--check-dependencies`) | LLM03 |
| DEP002 | Dependency name one edit away from a popular package (opt-in) | LLM03 |
| DEP003 | Dependency with a documented malicious release or critical CVE — checked offline on every scan (postmark-mcp, mcp-remote CVE-2025-6514, …) | LLM03 · MCP04 |

`secureai-scan explain <RULE_ID>` gives the exploit walkthrough and a before/after code example for any rule.

## MCP server (use it from Claude)

The package ships an MCP server exposing `scan_repository`, `explain_rule`, and `generate_bom`:

```json
{
  "mcpServers": {
    "secureai-scan": {
      "command": "node",
      "args": ["/path/to/secureai-scan/mcp-server/index.js"]
    }
  }
}
```

## The precision contract

False positives kill scanners. SecureAI-Scan's rule engine follows three hard rules:

1. **Sinks are resolved through imports.** If an identifier resolves to a module that is not an LLM SDK, it is definitively not an LLM call — no matter what it's named.
2. **Evidence is labeled, never blended.** A traced dataflow and a word-proximity match are not the same thing, so they never share a tier.
3. **The safe corpus gates every release.** [`test-fixtures/safe/`](test-fixtures/safe) contains the patterns that used to cause false positives (redacted PII payloads, Google Maps clients, env-var API keys next to LLM clients, ordinary response logging). Any finding there fails the suite.

## License

MIT © Akshay Kanthed
