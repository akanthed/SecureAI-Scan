# SecureAI-Scan

[![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-supported-yellow.svg)](https://www.python.org/)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen)](https://nodejs.org)
[![ChatGPT](https://img.shields.io/badge/ChatGPT-GPT%20available-74aa9c?logo=openai&logoColor=white)](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)
[![OWASP](https://img.shields.io/badge/OWASP-LLM%20%C2%B7%20ASI%20%C2%B7%20MCP%20Top%2010-000000)](#rules)

**The AI security scanner that proves its findings.**

SecureAI-Scan finds LLM, MCP, Agent Skill, and RAG vulnerabilities in **TypeScript, JavaScript, and Python** — and shows you the evidence: the exact source → flow → sink path for every dataflow finding, resolved through real imports, not keyword matching.

It's the first scanner mapped to **all three** OWASP AI security frameworks — the LLM Top 10, the [Top 10 for Agentic Applications (2026)](https://genai.owasp.org/), and the [MCP Top 10](https://owasp.org/www-project-mcp-top-10/) — with a coverage matrix in every threat model showing exactly which risks are checked and which are runtime concerns.

```
  ▌ HIGH  AI001  Prompt injection via user input
    PROVEN  LLM01 Prompt Injection

    source src/chat.ts:8   request data `req.body.input`
    flow   src/chat.ts:13  passed as `systemPrompt`
    sink   src/chat.ts:10  openai.chat.completions.create — system role (OpenAI)

    fix    Keep system prompts static; pass user input as a user-role message.
```

**Is this for you?** SecureAI-Scan is scoped deliberately to LLM, MCP, and RAG/agent risks — prompt injection, tool poisoning, unsafe output handling, vector-store access control, agent-skill poisoning. It is not a general SAST or secrets scanner, and doesn't try to be one; a known-malicious package with no LLM-shaped payload (e.g. a hardcoded exfiltration address in an email API call) is caught by the offline advisory list (`DEP003`), not a pattern rule. If your codebase talks to an LLM, an MCP server, a vector store, or ships Agent Skills, this is built for you.

## Contents

- [Why this scanner is different](#why-this-scanner-is-different)
- [Get started in 30 seconds](#get-started-in-30-seconds)
- [Commands](#commands)
- [GitHub Action](#github-action)
- [Rules](#rules)
- [MCP server (use it from Claude)](#mcp-server-use-it-from-claude)
- [Claude Skill](#claude-skill)
- [The precision contract](#the-precision-contract)
- [Testing & benchmarking](#testing--benchmarking)

## Why this scanner is different

- **Evidence tiers, not noise.** Every finding is `proven` (traced dataflow or parsed config fact), `likely` (resolved sink, one heuristic hop), or `heuristic`. **A default scan shows only proven + likely.** Heuristics are opt-in via `--paranoid`.
- **Import-resolved detection.** A call is only an "LLM call" if it resolves to a real SDK import (`openai`, `@anthropic-ai/sdk`, `ai`, `@google/genai`, LangChain, Bedrock, …). Your Google Maps client will never be flagged as an LLM again.
- **Precision-gated, and benchmarked against real repos.** The test suite asserts every vulnerable fixture fires *and* every safe fixture stays clean — a false positive on the safe corpus fails the build. Beyond that, every detection change is run against real public repos (OpenAI/Anthropic/Vercel AI SDKs, official MCP servers, LlamaIndex) before shipping. See [Testing & benchmarking](#testing--benchmarking) for the actual before/after numbers.
- **SARIF for GitHub code scanning.** `--output report.sarif` puts findings inline on pull requests and in the Security tab.
- **AI-BOM.** `secureai-scan bom .` inventories every SDK, model ID, vector store, agent framework, and MCP server in your repo — zero-false-positive by construction, mapped to OWASP LLM Top 10 / EU AI Act documentation needs.
- **MCP config scanning.** Parses `.mcp.json`, `claude_desktop_config.json`, `.cursor/mcp.json`: unpinned `npx -y` servers, inline secrets, plaintext HTTP transports.
- **MCP tool-poisoning detection.** Catches the pattern behind the WhatsApp MCP rug-pull and postmark-mcp backdoor — invisible Unicode, agent-directed injection phrases, and cross-tool shadowing in tool names/descriptions, statically, before you ever run the server.
- **MCP command-injection detection.** Flags MCP stdio transport `command`/`args` built from request data — the pattern behind the 2026 MCP STDIO RCE disclosure.
- **Agent Skill poisoning detection.** The same invisible-Unicode, injection-phrase, and shadowing checks applied to `SKILL.md` files — Agent Skills load into context wholesale, so a poisoned skill is a poisoned tool description by another name.
- **Known-malicious package advisories, version-aware.** Checks every dependency and every MCP-launched package against a curated advisory list (documented backdoors, critical CVEs) — offline, on every scan, no flag required. Clears a finding once you've actually upgraded past the affected range; stays flagged on any ambiguous or unpinned version, never silently.
- **Local-first.** Nothing leaves your machine.

## Get started in 30 seconds

```bash
npx --yes secureai-scan@latest scan .
```

TypeScript, JavaScript, Python, MCP config files, and Agent Skill (`SKILL.md`) files are scanned automatically — one command, no config.

> Prefer to ask questions first? Try the free **[SecureAI-Scan AI Security Advisor on ChatGPT](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)**.

> About to run an MCP server you found on GitHub or Twitter? Paste its tool description into **[MCP X-Ray](https://akanthed.github.io/SecureAI-Scan/)** first — checks it for hidden Unicode, injected instructions, and known-malicious packages in your browser, no install.

## Commands

The one you need 95% of the time:

```bash
secureai-scan scan .
```

Everything else is there when you need it. `secureai-scan scan . --help` shows all of this in the terminal, grouped the same way:

**Everyday**

| Flag | What it does |
|------|---------------|
| *(none)* | `proven` + `likely` findings — the default, no flags needed |
| `--paranoid` | also include `heuristic`-tier findings |
| `-s, --severity <level>` | only show findings at/above `low`\|`medium`\|`high`\|`critical` |
| `--output <file>` | write a full report — `.sarif` (GitHub code scanning), `.json`, `.md`, or `.html` |

**Scope which rules run**

| Flag | What it does |
|------|---------------|
| `-r, --rules <list>` | run only these rule IDs, e.g. `AI001,MCP007` |
| `--only-ai` / `--only-mcp` / `--only-vec` / `--only-skl` | run only one rule category |
| `--check-dependencies` | also check `package.json`/`requirements.txt` against the npm/PyPI registry for typos and hallucinated packages (`DEP001`/`DEP002`). Auto-enabled if you select those rules directly via `-r` — you never need to remember to pass both. Not needed for `DEP003` (known-malicious packages), which always runs offline |

**CI / workflow**

| Flag | What it does |
|------|---------------|
| `--fail-on <severity>` | exit `1` if findings at/above this severity exist |
| `--baseline <file>` | track only new/changed issues against a saved baseline |
| `--policy <file>` | load thresholds, skipped paths, and blocked rules from a `.secureai-policy.json` (auto-detected if present — `secureai-scan init` creates one) |

**Advanced**

| Flag | What it does |
|------|---------------|
| `--min-confidence <0-1>` | finer-grained than `--paranoid`: hide findings below an exact confidence score (`0.9` proven / `0.65` likely / `0.35` heuristic) |
| `--limit <n>` | max rule groups shown in the terminal (default `10`) — full detail always goes to `--output` |
| `--debug` | print every file scanned and which rules ran |

**Other commands:**

```bash
secureai-scan bom . --output AI_BOM.md   # AI Bill of Materials
secureai-scan explain AI001              # why + exploit + fix example, for any rule
secureai-scan threat-model .             # THREAT_MODEL.md with the OWASP coverage matrix
secureai-scan init                       # policy file + CI workflow, one-time setup
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

**32 rules**, every one mapped to the OWASP LLM Top 10 (2025) — plus, where applicable, the OWASP Top 10 for Agentic Applications (2026, ASI) and the OWASP MCP Top 10 (2025) — and, where relevant, an EU AI Act article. `threat-model` output includes a full coverage matrix across all three frameworks.

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
| MCP010 | MCP stdio server command/args constructed from user input (RCE) | LLM03 · MCP05 |
| SKL001 | Invisible/bidi Unicode in an Agent Skill file (`SKILL.md`) | LLM01 |
| SKL002 | Agent-directed injection phrasing in a skill's description or body | LLM01 |
| SKL003 | A skill's content steers when/how a different skill is used (shadowing) | LLM01 |
| VEC001 | Vector search without a tenant/user filter | LLM08 |
| VEC002 | Unbounded or user-controlled search limit | LLM10 |
| VEC003 | User content ingested into a shared vector store | LLM04 |
| VEC004 | Ingestion without tenant/namespace tagging | LLM08 |
| DEP001 | Dependency name not found in the registry (opt-in `--check-dependencies`) | LLM03 |
| DEP002 | Dependency name one edit away from a popular package (opt-in) | LLM03 |
| DEP003 | Dependency with a documented malicious release or critical CVE — checked offline on every scan, version-range aware (postmark-mcp, mcp-remote CVE-2025-6514, …) | LLM03 · MCP04 |

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

## Claude Skill

For Claude Code / Claude.ai users, [`skills/secureai-scan/SKILL.md`](skills/secureai-scan/SKILL.md) teaches Claude when to run a scan (reviewing AI/LLM code, or checking an MCP server/Agent Skill before you install it) and how to read the results — no separate process to run, unlike the MCP server above. Copy the `skills/secureai-scan/` directory into your `.claude/skills/` to use it.

## The precision contract

False positives kill scanners. SecureAI-Scan's rule engine follows three hard rules:

1. **Sinks are resolved through imports.** If an identifier resolves to a module that is not an LLM SDK, it is definitively not an LLM call — no matter what it's named.
2. **Evidence is labeled, never blended.** A traced dataflow and a word-proximity match are not the same thing, so they never share a tier.
3. **The safe corpus gates every release.** [`test-fixtures/safe/`](test-fixtures/safe) contains the patterns that used to cause false positives (redacted PII payloads, Google Maps clients, env-var API keys next to LLM clients, ordinary response logging, OAuth metadata fields, streaming-response `chunks`, fiction/narrative prompt text). Any finding there fails the suite.

## Testing & benchmarking

Three layers, because one alone isn't enough to trust a scanner's claims — precision and recall are different failure modes, and both get checked.

**1. Fixture corpus — precision + recall, runs on every build.**

```bash
npm test
```

[`test-fixtures/vulnerable/`](test-fixtures/vulnerable) and [`test-fixtures/safe/`](test-fixtures/safe) are scanned together: every vulnerable fixture must fire its expected rule at `proven`/`likely` evidence (recall), every safe fixture must produce **zero** `proven`/`likely` findings (precision). Fast and deterministic — but it only proves the scanner behaves on code written specifically to test it.

**2. Real-world regression benchmark — against public repos we didn't write.**

```bash
npm run regression                # scan the full curated repo set
npm run regression -- --fresh     # re-clone everything first
npm run regression -- openai-node # scan just one repo by name
```

[`scripts/regression-scan.js`](scripts/regression-scan.js) clones a curated, diverse set of real public repos (OpenAI/Anthropic/Vercel AI SDKs, the official MCP servers and TypeScript SDK, LlamaIndex — spanning TS and Python, SDK-consumer example code and SDK-author source) and scans each with the built CLI. There's no fixed pass/fail threshold — upstream repos change — so every `proven`/`likely` finding gets read against its source line by hand. Anything that isn't a genuine issue is a rule bug, fixed at the root cause and locked in permanently as a new `test-fixtures/safe/` fixture.

Real numbers from the last run (findings at default evidence level, no `--paranoid`):

| Repo | Before | After | What was wrong |
|------|-------:|------:|-----------------|
| [vercel/ai](https://github.com/vercel/ai) | 773 | 1 | `examples/`, top-level `tests/`, and hyphenated `ecosystem-tests/`-style directories weren't recognized as lower-trust paths; `chunks` (a common streaming-response variable) was treated as unambiguous RAG evidence |
| [openai/openai-node](https://github.com/openai/openai-node) | 47 | 0 | Same path-detection gap, applied to the SDK's own `examples/`/`ecosystem-tests/` |
| [anthropics/anthropic-sdk-typescript](https://github.com/anthropics/anthropic-sdk-typescript) | 2 | 0 | Same path-detection gap on a top-level `tests/` directory |
| [modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk) | 3 | 0 | `token_endpoint`/`tokenType`-style OAuth metadata fields flagged as leaked secrets |
| [run-llama/llama_index](https://github.com/run-llama/llama_index) | 18 | 15 | A Python check flagged any `description=` field containing "system prompt" as `proven` MCP tool poisoning, regardless of context. The remaining 15 are `VEC001` hits on the library's own generic retriever definitions — scanning a vector-DB SDK's own source, not application code, so a filter can't exist to check; an honest, inherent limit, not a bug |

The single remaining `vercel/ai` finding, and all `modelcontextprotocol/servers` / `anthropics/anthropic-sdk-python` results (zero, even at `--paranoid`), are genuine — reviewed by hand, not assumed.

**3. Vulnerable-vs-patched validation — proves recall, not just precision.**

The two layers above only check that the scanner stays quiet on safe code. `DEP003`'s advisory checks are validated the other way: pin a package to a documented-vulnerable version and confirm it's flagged, then pin it to the patched version and confirm it isn't.

```bash
node --test test/dependency-guard.test.js
```

covers: `mcp-remote@0.1.15` (CVE-2025-6514, vulnerable) flagged / `mcp-remote@0.1.16` (patched) clear; `postmark-mcp@1.0.15` (before the backdoor) clear / `postmark-mcp@1.0.20` (after — no legitimate patch exists for a malicious package) still flagged; an unpinned `^0.1.16` range still flagged despite being patchable, since we can't prove what actually resolves. Building this test caught a real gap: `DEP003` used to match advisories by package name only, never actually comparing the declared version against the advisory's affected range — fixed in [`src/scanner/semver.ts`](src/scanner/semver.ts), which clears a finding only when an exact version pin is provably outside the affected range, and fails toward flagging on anything ambiguous.

## License

MIT © Akshay Kanthed
