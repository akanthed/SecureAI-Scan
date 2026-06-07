# SecureAI-Scan

[![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue.svg)](https://www.typescriptlang.org/)
[![Node](https://img.shields.io/badge/node-%3E%3D22-brightgreen)](https://nodejs.org)

**Find AI/LLM security vulnerabilities in your code before attackers do.**

SecureAI-Scan is a CLI tool that scans TypeScript and JavaScript codebases for security issues specific to AI-powered apps — prompt injection, MCP tool abuse, RAG data poisoning, agent trust violations, and more.

- **Local-first** — nothing leaves your machine
- **Zero config** to start — one command, instant results
- **19 rules** across AI, MCP (Model Context Protocol), and Vector/RAG pipelines
- **Actionable** — every finding includes a code-level fix example

---

## Get Started in 30 Seconds

```bash
# Scan your repo right now — no install needed
npx --yes secureai-scan@latest scan .
```

That's it. You'll see findings in your terminal immediately.

---

## Your 4-Step Security Journey

The recommended path from first scan to CI enforcement:

### Step 1 — Set up (once per project)

```bash
npx --yes secureai-scan@latest init
```

This creates two files:
- `.secureai-policy.json` — your security policy (severity thresholds, rules, CI behavior)
- `.github/workflows/secureai-scan.yml` — a ready-to-use GitHub Actions workflow

### Step 2 — Scan and understand

```bash
# Scan with your policy applied
npx --yes secureai-scan@latest scan . --policy .secureai-policy.json

# Get a detailed HTML report to share with your team
npx --yes secureai-scan@latest scan . --output report.html

# Understand exactly what a rule means and how to fix it
npx --yes secureai-scan@latest explain AI001
```

### Step 3 — Create a baseline (track only new issues)

```bash
npx --yes secureai-scan@latest scan . --baseline .secureai-baseline.json
```

On first run: saves the current findings as your baseline.
On every run after: shows **only new issues** introduced since the baseline. Perfect for PRs.

### Step 4 — Generate a threat model

```bash
npx --yes secureai-scan@latest threat-model .
```

Writes a `THREAT_MODEL.md` with trust boundaries, realistic attack scenarios, and a prioritised fix list — ready for your security review or compliance audit.

---

## All Commands

| Command | What it does |
|---------|--------------|
| `secureai-scan init` | First-time setup: policy file + CI workflow + step-by-step guide |
| `secureai-scan scan <path>` | Scan a repo for vulnerabilities |
| `secureai-scan explain <RULE_ID>` | Show why a rule matters, how it's exploited, and a fix example |
| `secureai-scan threat-model <path>` | Generate a `THREAT_MODEL.md` |
| `secureai-scan prompt "<text>"` | Evaluate raw prompt text for injection risk |

### `scan` options

```bash
secureai-scan scan .                            # scan everything
secureai-scan scan . --only-ai                  # only AI/LLM rules
secureai-scan scan . --only-mcp                 # only MCP rules
secureai-scan scan . --only-vec                 # only Vector/RAG rules
secureai-scan scan . --rules AI001,MCP002       # specific rules only
secureai-scan scan . --severity high            # high and critical only
secureai-scan scan . --min-confidence 0.6       # strict: fewer, higher-confidence findings
secureai-scan scan . --output report.html       # save HTML report
secureai-scan scan . --output report.md         # save Markdown report
secureai-scan scan . --output report.json       # save JSON report
secureai-scan scan . --baseline baseline.json   # show only new issues
secureai-scan scan . --policy .secureai-policy.json  # enforce policy + CI exit code
secureai-scan scan . --check-dependencies       # check for hallucinated/typo packages
secureai-scan scan . --limit 10                 # show top 10 findings in terminal
secureai-scan scan . --debug                    # show scanned files and rule metadata
```

---

## Security Rules

### AI / LLM Rules

These cover the most common vulnerabilities in apps that call language model APIs.

| Rule | Severity | What it finds |
|------|----------|---------------|
| **AI001** | High | User input concatenated into an LLM prompt (prompt injection) |
| **AI002** | High | Prompts or responses logged with sensitive fields (email, token, etc.) |
| **AI003** | Critical | LLM called before authentication/authorization in a request handler |
| **AI004** | High | Entire user/session objects sent to an LLM (PII/secret leakage) |
| **AI005** | Critical | LLM output passed to `eval`, `exec`, SQL queries, or `innerHTML` |
| **AI006** | Critical | LLM given high-impact tools (delete, exec, email) with no approval gate |
| **AI007** | High | Retrieved RAG documents mixed directly into the system prompt |
| **AI008** | High | API keys or secrets found inside a system prompt string |
| **AI009** | Medium | User input sent to LLM with no token limit or input length cap |
| **AI010** | High | External HTTP/fetch response used in LLM prompt (indirect injection) |
| **AI011** | High | Upstream agent output placed in `system` role for a downstream agent |
| **AI012** | Medium | LLM response parsed with `JSON.parse` but not validated with a schema |

**Quick example — AI001 (Prompt Injection):**

```ts
// Vulnerable — user can override your instructions
const prompt = `You are a helpful assistant. User says: ${req.body.message}`;
await openai.chat.completions.create({ messages: [{ role: "user", content: prompt }] });

// Fixed — user input is isolated in its own role
await openai.chat.completions.create({
  messages: [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user",   content: String(req.body.message) },
  ],
});
```

---

### MCP Rules (Model Context Protocol)

MCP lets AI agents connect to external tool servers. These rules cover attacks specific to that protocol.

| Rule | Severity | What it finds |
|------|----------|---------------|
| **MCP001** | Critical | Tool description contains injection language ("ignore previous", "act as", etc.) |
| **MCP002** | Critical | MCP server URL constructed from user input (attacker controls your agent's tools) |
| **MCP003** | High | MCP tool result placed in `system`/`developer` role without validation |

**Quick example — MCP002 (Dynamic Server URL):**

```ts
// Vulnerable — attacker sends { mcpUrl: "https://evil.com/mcp" }
const server = { url: req.body.mcpUrl };
agent.connect(server);

// Fixed — only trusted servers allowed
const SERVERS = { search: "https://mcp.yourdomain.com/search" };
const url = SERVERS[req.body.tool];
if (!url) throw new Error("Unknown tool");
agent.connect({ url });
```

---

### Vector / RAG Rules

These cover security issues in Retrieval-Augmented Generation pipelines and vector databases.

| Rule | Severity | What it finds |
|------|----------|---------------|
| **VEC001** | High | Vector similarity search with no tenant/user filter (cross-user data leakage) |
| **VEC002** | Medium–High | Search result limit (`k`) from user input or unbounded (cost exhaustion / prompt stuffing) |
| **VEC003** | High | User-uploaded documents ingested into vector store without sanitization (data poisoning) |

**Quick example — VEC001 (No Access Control):**

```ts
// Vulnerable — returns documents from ALL users
const docs = await vectorStore.similaritySearch(query, 5);

// Fixed — scoped to the current user
const docs = await vectorStore.similaritySearch(query, 5, {
  filter: { userId: req.user.id },
});
```

---

### Dependency Rules (optional, `--check-dependencies`)

| Rule | Severity | What it finds |
|------|----------|---------------|
| **LLM_DEP001** | Low | Package name not found in npm/PyPI (hallucinated by an LLM) |
| **LLM_DEP002** | Low | Package name suspiciously similar to a popular package (typosquatting) |

---

## False Positive Control

Findings have a **confidence score** (0–1). The scanner filters out low-signal noise by default.

```bash
# Default: hide findings below 0.4 confidence
secureai-scan scan .

# Strict mode: only show high-confidence findings
secureai-scan scan . --min-confidence 0.6

# See everything (useful for initial triage)
secureai-scan scan . --min-confidence 0.1
```

The scanner automatically reduces confidence for:
- Test files (`*.test.ts`, `*.spec.ts`, `__tests__/**`)
- Code that already has sanitization functions nearby
- Embedding-only calls (not prompt-injection targets)

If a finding is a confirmed false positive, suppress it in code with a required reason:

```ts
// secureai-ignore AI001: sanitized via DOMPurify before this call
const prompt = buildPrompt(userInput);
```

Suppressed findings still appear in reports under **Ignored Findings** with your reason — so the audit trail is preserved.

---

## Policy File

Run `secureai-scan init` to create `.secureai-policy.json`, or write one manually:

```json
{
  "$comment": "Commit this file — CI will enforce it automatically",
  "minSeverity": "medium",
  "minConfidence": 0.45,
  "failOnSeverity": "high",
  "skipPaths": ["test/**", "examples/**"],
  "blockedRules": [],
  "onlyRules": [],
  "requireOutputValidation": true
}
```

| Field | What it does |
|-------|--------------|
| `minSeverity` | Hide findings below this severity |
| `minConfidence` | Hide findings below this confidence score |
| `failOnSeverity` | Exit with code 1 in CI if any finding meets this severity |
| `skipPaths` | Glob patterns to exclude from scanning |
| `blockedRules` | Rule IDs to always skip |
| `onlyRules` | Run only these rule IDs |

Apply it to a scan:

```bash
secureai-scan scan . --policy .secureai-policy.json
```

---

## CI / GitHub Actions

`secureai-scan init` creates `.github/workflows/secureai-scan.yml` automatically.

Or add this to an existing workflow:

```yaml
- name: AI Security Scan
  run: |
    npm install -g secureai-scan
    secureai-scan scan . \
      --policy .secureai-policy.json \
      --baseline .secureai-baseline.json \
      --output secureai-report.html

- name: Upload Report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: secureai-report
    path: secureai-report.html
```

With `"failOnSeverity": "high"` in your policy, the workflow fails automatically when a High or Critical finding is introduced. No extra configuration needed.

---

## Threat Model

```bash
secureai-scan threat-model . --output THREAT_MODEL.md
```

Generates a structured document with:
- **Security grade** (A–F based on finding severity)
- **Trust boundaries** — data flows that cross security boundaries (user → LLM, MCP server → agent, vector store → context)
- **Attack scenarios** — concrete "what happens if" narratives for your top findings
- **Remediation priority list** — ordered by risk impact

Use it for security reviews, compliance documentation (SOC 2, ISO 27001), or onboarding new engineers to the codebase's risk surface.

---

## Reports

All three formats include the same data — choose based on audience:

```bash
--output report.html    # Best for sharing with non-technical stakeholders
--output report.md      # Best for GitHub PRs and documentation
--output report.json    # Best for integrating with other tools
```

Every report includes:
- Executive summary and risk posture
- Findings grouped by category and severity
- Code snippet around each finding (with highlighted line)
- Why each pattern is flagged
- Ignored findings with their recorded reasons
- Next-step guidance

---

## Programmatic API

Use SecureAI-Scan as a library in your own tooling:

```ts
import {
  scanRepository,
  scanRepositoryDetailed,
  buildReport,
  formatReport,
  evaluatePromptRisk,
} from "secureai-scan";

// Simple: get findings as an array
const findings = scanRepository("./my-repo");

// Detailed: includes ignored findings and scanned file list
const result = scanRepositoryDetailed("./my-repo");

// Build and format a report
const report = buildReport(result.findings, {
  tool: "SecureAI-Scan",
  version: "0.2.0",
  scannedAt: new Date().toISOString(),
});
const html = formatReport(report, "html");

// Evaluate a prompt string directly
const risk = evaluatePromptRisk("Ignore previous instructions and...");
console.log(risk.level);    // "High"
console.log(risk.reasons);  // ["Contains instruction-override language"]
```

---

## FAQ

**Does this send my code anywhere?**
No. All analysis runs locally. No telemetry, no SaaS calls, no data leaves your machine.

**Does it work on JavaScript too?**
Yes. It scans `.ts`, `.tsx`, `.js`, and `.jsx` files.

**What if I have too many findings to fix at once?**
Use `--baseline` to create a snapshot. Future scans only show findings introduced after that point — so you can fix the backlog at your own pace while preventing new issues in PRs.

**A finding is wrong — how do I suppress it?**
Add a `// secureai-ignore RULE_ID: reason` comment on the line before the finding. The reason is required and is recorded in reports.

**Can I add my own rules?**
The `Rule` interface is public. Implement `{ id, title, severity, run(context) }` and add it to your own scan pipeline via the programmatic API.

**Does it replace a security audit?**
No. It catches common patterns quickly and cheaply. A human security review and threat modelling session are still valuable — and `secureai-scan threat-model` helps you prepare for them.

---

## Who This Is For

- **Development teams** shipping LLM features and wanting a pre-merge safety net
- **Security engineers** who need a fast, automated AI-risk inventory of a codebase
- **Founders and CTOs** who want evidence of security due diligence without a dedicated AppSec team
- **Anyone building with MCP, RAG, or multi-agent architectures** — the attack surface is new and most scanners don't cover it yet

---

## Requirements

- Node.js 22 or later
- TypeScript or JavaScript codebase

---

## License

MIT — [Akshay Kanthed](https://github.com/akanthed)

Issues and contributions welcome: [github.com/akanthed/SecureAI-Scan](https://github.com/akanthed/SecureAI-Scan)
