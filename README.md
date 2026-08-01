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
- [How it compares](#how-it-compares)
- [Get started in 30 seconds](#get-started-in-30-seconds)
- [See it work](#see-it-work)
- [Commands](#commands)
- [GitHub Action](#github-action)
- [Rules](#rules)
- [Architecture](#architecture)
- [MCP server (use it from Claude)](#mcp-server-use-it-from-claude)
- [Claude Skill](#claude-skill)
- [The precision contract](#the-precision-contract)
- [Testing & benchmarking](#testing--benchmarking)
- [Roadmap](#roadmap)
- [Contributing](#contributing)

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
- **Evasion-resistant skill scanning.** Skill bundles are scanned as *directories*, not just their `SKILL.md`, and every content check runs against deobfuscated variants of the text. This targets the published techniques — homoglyphs, zero-width splitting, payloads staged in `.git/` or `build/`, exfiltration hidden in a `*.test.ts` file — that bypassed **>90% of the nine scanners** surveyed in *Cloak and Detonate* (arXiv:2607.02357). See [Evasion resistance](#evasion-resistance).
- **Known-malicious package advisories, version-aware.** Checks every dependency and every MCP-launched package against a curated advisory list (documented backdoors, critical CVEs) — offline, on every scan, no flag required. Clears a finding once you've actually upgraded past the affected range; stays flagged on any ambiguous or unpinned version, never silently.
- **Local-first.** Nothing leaves your machine.

## How it compares

SecureAI-Scan is not a replacement for a general SAST tool or a container/IaC scanner — run it alongside one, not instead of one. It's the only one of these purpose-built for the LLM/MCP/RAG attack surface with dataflow evidence, not keyword rules.

| | SecureAI-Scan | Semgrep (OSS rules) | Trivy | GitHub Advanced Security |
|---|---|---|---|---|
| Prompt injection (source→sink traced) | ✅ import-resolved dataflow | ⚠️ pattern rules only, community-maintained | ❌ | ⚠️ CodeQL can, but no AI-specific ruleset |
| MCP tool-poisoning / config risk | ✅ MCP007–010, config scanner | ❌ | ❌ | ❌ |
| Agent Skill poisoning (`SKILL.md`) | ✅ evasion-resistant, bundle-aware | ❌ | ❌ | ❌ |
| RAG / vector-store misconfig | ✅ VEC001–004 | ❌ | ❌ | ❌ |
| Known-malicious AI package advisories | ✅ DEP003, offline, version-aware | ❌ | ⚠️ general CVE feed, not AI-specific | ⚠️ Dependabot, general CVE feed |
| General SAST (SQLi, XSS, path traversal) | ❌ out of scope by design | ✅ | ❌ | ✅ |
| Container / IaC scanning | ❌ | ❌ | ✅ | ⚠️ via CodeQL/Actions |
| Evidence tiers (proven/likely/heuristic) | ✅ | ❌ findings are flat | ❌ | ⚠️ CodeQL has some, not AI-tuned |
| SARIF output (GitHub code scanning) | ✅ | ✅ | ✅ | native |
| Runs offline, no account | ✅ | ✅ (OSS rules) | ✅ | ❌ requires GitHub |

If you already run Semgrep or GHAS, keep them — add SecureAI-Scan for the risk surface they don't model at all.

## Get started in 30 seconds

```bash
npx --yes secureai-scan@latest scan .
```

TypeScript, JavaScript, Python, MCP config files, and Agent Skill (`SKILL.md`) files are scanned automatically — one command, no config.

> Prefer to ask questions first? Try the free **[SecureAI-Scan AI Security Advisor on ChatGPT](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)**.

> About to run an MCP server you found on GitHub or Twitter? Paste its tool description into **[MCP X-Ray](https://akanthed.github.io/SecureAI-Scan/)** first — checks it for hidden Unicode, injected instructions, and known-malicious packages in your browser, no install.

## See it work

<!-- TODO: terminal recording of `secureai-scan scan .` end-to-end, from npx invocation to the evidence-tiered report. Keep it small (compress, or host as a GitHub release asset rather than a raw repo file). No demo GIF exists yet; don't add an <img>/markdown reference here until one is actually committed or hosted, or it renders as a broken image on GitHub. -->

Attack shapes the scanner traces end to end:

| MCP tool-poisoning dataflow | RAG context-injection dataflow |
|---|---|
| ![MCP attack trace](mcp-attack-diagram.png) | ![RAG poisoning trace](rag-poisoning-diagram.png) |

<!-- Screenshots section: add a terminal screenshot of the SARIF-annotated GitHub PR view, and one of `--output report.html` rendered, once available. -->

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

**Scan before you install — no clone, no config:**

```bash
secureai-scan skill anthropics/skills          # a GitHub "owner/repo" shorthand
secureai-scan skill https://github.com/…       # or a full git URL
secureai-scan skill ./some/local/skill-dir     # or a local path
secureai-scan mcp some-mcp-server-package      # a bare npm package name
secureai-scan mcp owner/mcp-server-repo        # or git, same as `skill`
```

`skill` and `mcp` fetch the target and scan it, then delete the fetched copy (`--keep` to inspect it instead). Nothing fetched is ever executed: an npm target is downloaded with `npm pack` — the tarball only, no `install`, no lifecycle scripts — and a git target is a plain `git clone --depth 1`. This is the moment that matters most: before a skill lands in `~/.claude/skills/` or a server lands in `.mcp.json`, not after.

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

**35 rules**, every one mapped to the OWASP LLM Top 10 (2025) — plus, where applicable, the OWASP Top 10 for Agentic Applications (2026, ASI) and the OWASP MCP Top 10 (2025) — and, where relevant, an EU AI Act article. `threat-model` output includes a full coverage matrix across all three frameworks.

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
| SKL001 | Invisible/bidi Unicode anywhere in an Agent Skill bundle | LLM01 |
| SKL002 | Agent-directed injection phrasing in a skill's description or body (matched through obfuscation) | LLM01 |
| SKL003 | A skill's content steers when/how a different skill is used (shadowing) | LLM01 |
| SKL004 | Staged/self-extracting payload: opaque blob + instructions to decode and run it | LLM03 · MCP04 |
| SKL005 | Credential read + hardcoded external egress in a bundle companion file | LLM02 · MCP04 |
| VEC001 | Vector search without a tenant/user filter | LLM08 |
| VEC002 | Unbounded or user-controlled search limit | LLM10 |
| VEC003 | User content ingested into a shared vector store | LLM04 |
| VEC004 | Ingestion without tenant/namespace tagging | LLM08 |
| DEP001 | Dependency name not found in the registry (opt-in `--check-dependencies`) | LLM03 |
| DEP002 | Dependency name one edit away from a popular package (opt-in) | LLM03 |
| DEP003 | Dependency with a documented malicious release or critical CVE — checked offline on every scan, version-range aware (postmark-mcp, mcp-remote CVE-2025-6514, …) | LLM03 · MCP04 |

`secureai-scan explain <RULE_ID>` gives the exploit walkthrough and a before/after code example for any rule.

## Architecture

Three independent scanning surfaces feed one merged, deduped finding list:

```
                    ┌─────────────────────┐
  *.ts / *.js  ───▶ │  ts-morph AST rules │───┐
                    │  (import-resolved   │   │
                    │   sinks + dataflow) │   │
                    └─────────────────────┘   │
                                               │
                    ┌─────────────────────┐   │      ┌──────────────┐      ┌─────────────────┐
  *.py         ───▶ │  Python regex +     │───┼───▶  │  scan.ts     │───▶  │  evidence filter │
                    │  taint-propagation  │   │      │  merge/dedupe│      │  → confidence    │
                    └─────────────────────┘   │      │  + suppress  │      │  → severity      │
                                               │      │  (// secure- │      │  → baseline diff │
  .mcp.json,         ┌─────────────────────┐  │      │  ai-ignore)  │      │  → report        │
  SKILL.md      ───▶ │  Config/bundle scan │──┘      └──────────────┘      └─────────────────┘
                    │  (off-disk, evasion- │                                        │
                    │   resistant)         │                                        ▼
                    └─────────────────────┘                         terminal · sarif · json · md · html

  package.json,
  requirements.txt ─▶ dependency-guard.ts (advisories.ts, offline, version-aware)
```

Every AST rule only calls a function an "LLM call" if it resolves through real imports to a known SDK — never by name-matching alone. See [`docs/Architecture.md`](docs/Architecture.md) for the full breakdown of each surface, and [`docs/DetectionEngine.md`](docs/DetectionEngine.md) for how the evidence-tier contract works.

## MCP server (use it from Claude)

The package ships an MCP server exposing `scan_repository`, `explain_rule`, `generate_bom`, and `scan_untrusted_target` (fetch and scan a skill or MCP server before Claude recommends installing it — same fetch-without-executing behavior as the `skill`/`mcp` CLI commands):

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

## Evasion resistance

In July 2026, two pieces of public research showed that Agent Skill scanners are trivially bypassed.

**[Cloak and Detonate](https://arxiv.org/abs/2607.02357)** (Ji, Xu, Li, Gao, Wei, Wang & Cheung — HKUST, arXiv:2607.02357) ran an adversarial study against **nine** published skill scanners using 1,613 in-the-wild malicious skills. Two attack families, both of which preserve the payload exactly:

- **Reify** — rewrite the bytes a rule matches, while the agent still reassembles the original at runtime. **>80% bypass** on most static scanners.
- **Disperse / SFS packing** — move the payload outside the rule's scope: into a directory the scanner skips, behind a renamed extension, or archived and encoded into `.git/`, with a benign cover `SKILL.md` that rebuilds it on first run. **≥90% bypass on every scanner tested**, ≥96% on most. One hybrid scanner's detection rate fell from ~99% to ~10%.

Separately, **Gecko Security** ([VentureBeat](https://venturebeat.com/security/anthropic-skill-scanners-passed-every-check-malicious-code-test-file)) shipped a payload in a `*.test.ts` file. Every public scanner skipped it — but Jest and Vitest auto-discover and execute those files on the next `npm test`.

SecureAI-Scan handles each published technique. Every row below has a corresponding test in [`test/deobfuscate.test.js`](test/deobfuscate.test.js) or a fixture in [`test-fixtures/vulnerable/skills/`](test-fixtures/vulnerable/skills):

| Technique (paper's name) | Example | How it's handled |
|---|---|---|
| Zero-width insertion | `Ign‍ore all pre‍vious…` | Text is matched against invisible-stripped variants |
| Confusable glyphs | `сurl` (Cyrillic `с`) | Homoglyph folding to ASCII before matching |
| Case flip | `EvAl` | All content patterns are case-insensitive |
| Variable splicing | `'cu' + 'rl'` | Adjacent string literals joined before matching |
| Per-line splitting | `ev`⏎`al(x)` | Intra-word line breaks joined as an extra variant |
| Per-file extraction | payload in a sourced helper | Whole bundle is scanned, not just `SKILL.md` |
| Directory relocation | `scripts/x.sh` → `build/x.sh` | No directory skip-list inside a bundle |
| Extension renaming | `x.sh` → `x.txt` | Files are scanned by content, not extension |
| Size padding | pad past the scanner's cap | Oversized files are head-read, never skipped |
| SFS packing | payload in `.git/skillpack.dat` | Any non-git file under a bundle's `.git/` is `proven` (SKL004) |
| Test-file staging | payload in `*.test.ts` | Bundle scanning deliberately does **not** demote test paths (SKL005) |

### This does not weaken the precision contract

Deobfuscation is usually a precision risk — more matches, more noise. Here the logic is inverted: **a match that appears only after deobfuscation is promoted to `proven`, not demoted.** Ordinary documentation does not contain a zero-width joiner inside "ignore previous instructions", nor a Cyrillic `с` inside `curl`. The concealment is itself affirmative evidence of intent.

The comparison is against the *set* of raw matches, not merely "did the raw text match at all" — otherwise an attacker could mask the signal by leaving one innocuous phrase in the clear.

The two new bundle rules fire only on conjunctions, never on a keyword:

- **SKL004** needs an opaque blob **and** an unpack directive that *references that blob by name* — a README mentioning `tar -x` next to an unrelated binary asset is not enough. Real archives (gzip/zip/png/pdf/wasm — checked by magic bytes, not extension) are never "opaque" in the first place, however they're compressed.
- **SKL005** needs a concrete credential *signal* — a path (`~/.aws/credentials`, not the word "token") or bulk environment-variable enumeration (`os.environ.items()`, not `os.environ["API_KEY"]`) — **and** egress to a hardcoded non-local host, **within 25 lines of each other in the same file**, or a remote fetch that gets executed after being reassigned through one or more renames. A publish helper that reads `~/.npmrc` in one function and calls a registry forty lines later stays clean, and reading one named env var for an API call is never flagged — both shapes are pinned as safe fixtures.

Validated against two real-world corpora, not just fixtures we wrote ourselves: **0 findings across all 18 real skill bundles in [anthropics/skills](https://github.com/anthropics/skills)** and all 14 in vercel/ai, and **6/6 correct on [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)'s labeled eval corpus** (20 skills, each with an `_expected.json` verdict) with zero false positives on anything labeled safe. See [Testing & benchmarking](#testing--benchmarking).

### What this is not

Honest limitation: the paper's conclusion is that runtime detonation beats static analysis, and that is correct. An adaptive adversary who knows these rules can write a transformation they don't cover. What changes here is the *cost* of evasion — the published, currently-circulating techniques no longer work, and the obfuscation needed to defeat them now itself raises the finding's severity. **Static scanning is a filter, not a security boundary.** Treat an untrusted skill as untrusted code regardless of what any scanner says.

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

[`scripts/regression-scan.js`](scripts/regression-scan.js) clones a curated, diverse set of real public repos (OpenAI/Anthropic/Vercel AI SDKs, the official MCP servers and TypeScript SDK, LlamaIndex, plus [anthropics/skills](https://github.com/anthropics/skills) and [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) for skill-bundle coverage — spanning TS and Python, SDK-consumer example code and SDK-author source) and scans each with the built CLI. There's no fixed pass/fail threshold — upstream repos change — so every `proven`/`likely` finding gets read against its source line by hand. Anything that isn't a genuine issue is a rule bug, fixed at the root cause and locked in permanently as a new `test-fixtures/safe/` fixture.

**Skill-bundle coverage gets its own line** because `cisco-ai-defense/skill-scanner`'s `evals/` corpus is labeled — each of its 20 fixtures ships an `_expected.json` verdict and sits under a directory literally named `malicious/` or `safe/`, so it doubles as a recall check, not just a precision one: **6/6 in-scope malicious fixtures fire, 0 findings on anything labeled safe**, and 0 findings across all 18 real bundles in `anthropics/skills` and all 14 in `vercel/ai`. (The remaining Cisco categories — SQL injection, path traversal, resource exhaustion, generic `eval()` of a function argument, a payload deliberately split across four files — are either out of the documented LLM/MCP/RAG scope or beyond same-file conjunction analysis; see the [0.6.0 changelog entry](CHANGELOG.md) for the specific reasoning on each.)

Historical before/after from the run that drove the original precision fixes (findings at default evidence level, no `--paranoid`):

| Repo | Before | After | What was wrong |
|------|-------:|------:|-----------------|
| [vercel/ai](https://github.com/vercel/ai) | 773 | 1 | `examples/`, top-level `tests/`, and hyphenated `ecosystem-tests/`-style directories weren't recognized as lower-trust paths; `chunks` (a common streaming-response variable) was treated as unambiguous RAG evidence |
| [openai/openai-node](https://github.com/openai/openai-node) | 47 | 0 | Same path-detection gap, applied to the SDK's own `examples/`/`ecosystem-tests/` |
| [anthropics/anthropic-sdk-typescript](https://github.com/anthropics/anthropic-sdk-typescript) | 2 | 0 | Same path-detection gap on a top-level `tests/` directory |
| [modelcontextprotocol/typescript-sdk](https://github.com/modelcontextprotocol/typescript-sdk) | 3 | 0 | `token_endpoint`/`tokenType`-style OAuth metadata fields flagged as leaked secrets |
| [run-llama/llama_index](https://github.com/run-llama/llama_index) | 18 | 15 | A Python check flagged any `description=` field containing "system prompt" as `proven` MCP tool poisoning, regardless of context. The remaining 15 are `VEC001` hits on the library's own generic retriever definitions — scanning a vector-DB SDK's own source, not application code, so a filter can't exist to check; an honest, inherent limit, not a bug |

**Current run (v0.6.0, 2026-07-28)** — upstream repos have grown substantially since the table above, so the counts have moved:

| Repo | Findings | Rules | Status |
|------|---------:|-------|--------|
| openai-node, anthropic-sdk-typescript, anthropic-sdk-python, modelcontextprotocol/typescript-sdk, modelcontextprotocol/servers | 0 | — | clean |
| [anthropics/skills](https://github.com/anthropics/skills) (18 real skill bundles) | 0 | — | clean — pure precision check for SKL001–005 |
| [vercel/ai](https://github.com/vercel/ai) (5,511 files) | 0 | — | **was 40** (AI001, AI003, AI005, AI010, MCP002) before triage — every one hand-reviewed against source and confirmed a false positive, traced to 3 independent root-cause bugs (see below), fixed, and re-confirmed clean on a full re-scan |
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

covers: `mcp-remote@0.1.15` (CVE-2025-6514, vulnerable) flagged / `mcp-remote@0.1.16` (patched) clear; `postmark-mcp@1.0.15` (before the backdoor) clear / `postmark-mcp@1.0.20` (after — no legitimate patch exists for a malicious package) still flagged; an unpinned `^0.1.16` range still flagged despite being patchable, since we can't prove what actually resolves. Building this test caught a real gap: `DEP003` used to match advisories by package name only, never actually comparing the declared version against the advisory's affected range — fixed in [`src/scanner/semver.ts`](src/scanner/semver.ts), which clears a finding only when an exact version pin is provably outside the affected range, and fails toward flagging on anything ambiguous.

## Roadmap

See [`ROADMAP.md`](ROADMAP.md) for what's shipped and what's planned — the short version: the Python scanner is regex-based today (a documented, deliberate trade-off, not an oversight — see [`docs/DetectionEngine.md`](docs/DetectionEngine.md)), and moving it to full AST analysis is the largest planned change.

## Contributing

Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the workflow, and [`docs/WritingRules.md`](docs/WritingRules.md) / [`docs/RuleDevelopment.md`](docs/RuleDevelopment.md) for how to add a detection rule that meets the precision bar above. Every new rule needs a fixture in both [`test-fixtures/vulnerable/`](test-fixtures/vulnerable) and [`test-fixtures/safe/`](test-fixtures/safe), an entry in `src/scanner/catalog.ts`, and a case in `test/corpus.test.js` — `npm test` enforces all three.

## License

MIT © Akshay Kanthed
