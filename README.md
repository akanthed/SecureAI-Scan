# SecureAI-Scan

[![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan)
[![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue.svg)](https://www.typescriptlang.org/)
[![Python](https://img.shields.io/badge/Python-supported-yellow.svg)](https://www.python.org/)
[![Node](https://img.shields.io/badge/node-%3E%3D22-brightgreen)](https://nodejs.org)
[![ChatGPT](https://img.shields.io/badge/ChatGPT-GPT%20available-74aa9c?logo=openai&logoColor=white)](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)

**Find AI/LLM security vulnerabilities in your code before attackers do.**

SecureAI-Scan is a CLI tool that scans **TypeScript, JavaScript, and Python** codebases for security issues specific to AI-powered apps — prompt injection, MCP tool abuse, RAG data poisoning, agent trust violations, and more.

- **Local-first** — nothing leaves your machine
- **Zero config** to start — one command, instant results
- **19 rules** across AI/LLM, MCP (Model Context Protocol), and Vector/RAG pipelines
- **TypeScript + Python** — covers both major AI developer ecosystems
- **Actionable** — every finding includes a code-level fix example

---

## Get Started in 30 Seconds

```bash
# Scan your repo right now — no install needed
npx --yes secureai-scan@latest scan .
```

Works on TypeScript, JavaScript, and Python files automatically. You'll see color-coded findings in your terminal immediately.

> **Prefer to ask questions first?** Try the free **[SecureAI-Scan AI Security Advisor on ChatGPT](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)** — paste your code, ask about a rule, or get a security review without installing anything.

---

## Your 4-Step Security Journey

### Step 1 — Set up (once per project)

```bash
npx --yes secureai-scan@latest init
```

Creates two files:
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

First run saves the current findings as your baseline. Every run after shows **only new issues** introduced since then — perfect for PRs.

### Step 4 — Generate a threat model

```bash
npx --yes secureai-scan@latest threat-model .
```

Writes `THREAT_MODEL.md` with trust boundaries, realistic attack scenarios, and a prioritised fix list — ready for security review or compliance audits.

---

## All Commands

| Command | What it does |
|---------|--------------|
| `secureai-scan init` | First-time setup: policy file + CI workflow |
| `secureai-scan scan <path>` | Scan a repo for AI/LLM/MCP/RAG vulnerabilities |
| `secureai-scan explain <RULE_ID>` | Show why a rule matters, how it's exploited, and a fix |
| `secureai-scan threat-model <path>` | Generate `THREAT_MODEL.md` |
| `secureai-scan prompt "<text>"` | Evaluate raw prompt text for injection risk |

### `scan` options

```bash
secureai-scan scan .                            # scan everything (TS, JS, Python)
secureai-scan scan . --only-ai                  # only AI/LLM rules (AI001–AI012)
secureai-scan scan . --only-mcp                 # only MCP rules (MCP001–MCP003)
secureai-scan scan . --only-vec                 # only Vector/RAG rules (VEC001–VEC003)
secureai-scan scan . --rules AI001,MCP002       # specific rules only
secureai-scan scan . --severity high            # high and critical only
secureai-scan scan . --min-confidence 0.6       # stricter: fewer, higher-confidence findings
secureai-scan scan . --output report.html       # save HTML report
secureai-scan scan . --output report.md         # save Markdown report
secureai-scan scan . --output report.json       # save JSON report
secureai-scan scan . --baseline baseline.json   # show only new issues since baseline
secureai-scan scan . --policy .secureai-policy.json  # enforce policy + CI exit code
secureai-scan scan . --check-dependencies       # check for hallucinated/typo packages
secureai-scan scan . --limit 10                 # show top 10 findings in terminal
secureai-scan scan . --debug                    # show file counts and rule metadata
```

---

## Security Rules

### AI / LLM Rules

Covers the most common vulnerabilities in apps that call language model APIs — works in **TypeScript and Python**.

| Rule | Severity | What it finds |
|------|----------|---------------|
| **AI001** | High | User input concatenated into an LLM prompt without role separation (prompt injection) |
| **AI002** | High | Prompts or responses logged with sensitive fields (email, token, completion text) |
| **AI003** | Critical | LLM called before authentication/authorization in a route handler |
| **AI004** | High | Entire user/session objects sent to an LLM (PII and secret leakage) |
| **AI005** | Critical | LLM output passed to `eval`, `exec`, subprocess, SQL queries, or `innerHTML` |
| **AI006** | Critical | LLM given high-impact tools (delete, execute, email) with no human approval gate |
| **AI007** | High | Retrieved RAG documents mixed directly into the system prompt as trusted instructions |
| **AI008** | High | API keys or secrets hardcoded inside a system prompt string |
| **AI009** | Medium | User input sent to LLM with no token limit or input length cap |
| **AI010** | High | External HTTP/fetch response piped directly into an LLM prompt (indirect injection) |
| **AI011** | High | Upstream agent output placed in `system` role for a downstream agent (trust boundary) |
| **AI012** | Medium | LLM response parsed with `JSON.parse` / `json.loads` but not validated with a schema |

**Example — AI001 (Prompt Injection) in Python:**

```python
# Vulnerable — user can override your system instructions
user_msg = request.json["message"]
response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": f"You are a helpful assistant. {user_msg}"}]
)

# Fixed — user input is isolated in its own role
response = client.chat.completions.create(
    model="gpt-4",
    messages=[
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user",   "content": str(user_msg)},
    ]
)
```

**Example — AI001 in TypeScript:**

```ts
// Vulnerable
const prompt = `You are a helpful assistant. User says: ${req.body.message}`;
await openai.chat.completions.create({ messages: [{ role: "user", content: prompt }] });

// Fixed
await openai.chat.completions.create({
  messages: [
    { role: "system", content: "You are a helpful assistant." },
    { role: "user",   content: String(req.body.message) },
  ],
});
```

---

### MCP Rules (Model Context Protocol)

MCP lets AI agents connect to external tool servers. These rules cover attacks specific to that architecture.

| Rule | Severity | What it finds |
|------|----------|---------------|
| **MCP001** | Critical | Tool description contains injection language ("ignore previous instructions", "act as", etc.) |
| **MCP002** | Critical | MCP server URL constructed from user input — attacker controls which tools your agent uses |
| **MCP003** | High | MCP tool result promoted to `system`/`developer` role without validation |

**Example — MCP002 (Dynamic Server URL):**

```ts
// Vulnerable — attacker sends { mcpUrl: "https://evil.com/mcp" }
const server = { url: req.body.mcpUrl };
agent.connect(server);

// Fixed — only pre-approved servers allowed
const TRUSTED_SERVERS = { search: "https://mcp.yourdomain.com/search" };
const url = TRUSTED_SERVERS[req.body.tool];
if (!url) throw new Error("Unknown tool");
agent.connect({ url });
```

---

### Vector / RAG Rules

Covers security issues in Retrieval-Augmented Generation pipelines and vector databases — detects patterns in **TypeScript and Python** (LangChain, Pinecone, Chroma, Weaviate, pgvector, and more).

| Rule | Severity | What it finds |
|------|----------|---------------|
| **VEC001** | High | Vector similarity search with no user/tenant filter — User A retrieves User B's documents |
| **VEC002** | Medium–High | Result count (`k`) comes from user input or has no upper bound (cost exhaustion / prompt stuffing) |
| **VEC003** | High | User-uploaded content ingested into shared vector store without sanitization (data poisoning) |

**Example — VEC001 (No Access Control) in Python:**

```python
# Vulnerable — returns documents from ALL users
docs = vectorstore.similarity_search(query, k=5)

# Fixed — scoped to the current user
docs = vectorstore.similarity_search(
    query, k=5, filter={"user_id": current_user.id}
)
```

---

### Dependency Rules (optional, `--check-dependencies`)

| Rule | Severity | What it finds |
|------|----------|---------------|
| **LLM_DEP001** | Low | Package name not found in npm/PyPI (possibly hallucinated by an LLM) |
| **LLM_DEP002** | Low | Package name suspiciously similar to a popular package (typosquatting risk) |

---

## False Positive Control

Every finding has a **confidence score** (0–1). Low-signal noise is filtered out by default.

```bash
# Default: hide findings below 0.4 confidence
secureai-scan scan .

# Strict mode: only high-confidence findings
secureai-scan scan . --min-confidence 0.6

# See everything (useful for initial triage)
secureai-scan scan . --min-confidence 0.1
```

Confidence is automatically reduced for:
- Test files (`*.test.ts`, `*_test.py`, `conftest.py`, `__tests__/**`)
- Code that already has sanitization nearby (`bleach`, `DOMPurify`, `validate`, etc.)
- Embedding-only calls (not prompt-injection targets)

Suppress a confirmed false positive in code with a required reason:

```ts
// secureai-ignore AI001: sanitized via DOMPurify before this call
const prompt = buildPrompt(userInput);
```

```python
# secureai-ignore AI001: input validated against allowlist above
response = client.chat.completions.create(...)
```

Suppressed findings still appear in reports under **Ignored Findings** with your reason — the audit trail is preserved.

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
| `failOnSeverity` | Exit with code 1 in CI when any finding meets this severity |
| `skipPaths` | Glob patterns to exclude from scanning |
| `blockedRules` | Rule IDs to always skip |
| `onlyRules` | Run only these rule IDs |

Apply it:

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

## Use with Claude (MCP Server)

SecureAI-Scan ships a built-in MCP server so you can scan repos and get security explanations directly from Claude Desktop or any MCP-compatible client.

### Setup

Add to your Claude Desktop config (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secureai-scan": {
      "command": "node",
      "args": ["/absolute/path/to/secureai-scan/mcp-server/index.js"]
    }
  }
}
```

> **Config file locations:**
> - Mac: `~/Library/Application Support/Claude/claude_desktop_config.json`
> - Windows: `%APPDATA%\Claude\claude_desktop_config.json`

### Available MCP Tools

Once connected, Claude has three tools:

| Tool | What it does |
|------|--------------|
| `scan_repository` | Scan a local path, returns structured findings with severity and confidence |
| `explain_rule` | Get a full explanation for any of the 19 rule IDs |
| `evaluate_prompt` | Check raw prompt text for injection risk patterns |

### Example Claude conversation

> **You:** Scan `/Users/me/my-langchain-app` for security issues  
> **Claude:** *(calls `scan_repository`)* Found 4 findings — 1 Critical (AI003: LLM called before auth in `app.py:24`), 2 High (AI001, VEC001), 1 Medium. Want me to explain the Critical finding and show you the fix?

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

Use it for security reviews, compliance documentation (SOC 2, ISO 27001), or onboarding engineers to the codebase's risk surface.

---

## Reports

All three formats include the same data — choose based on audience:

```bash
--output report.html    # Best for sharing with non-technical stakeholders
--output report.md      # Best for GitHub PRs and documentation
--output report.json    # Best for integrating with other tools / SIEM
```

Every report includes: executive summary, findings by category and severity, why each pattern is flagged, ignored findings with recorded reasons, and next-step guidance.

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

// Simple: get findings as an array (TypeScript + Python files)
const findings = scanRepository("./my-repo");

// Detailed: includes ignored findings, TS file list, Python file list
const result = scanRepositoryDetailed("./my-repo");
console.log(`TS/JS files: ${result.scannedFiles.length}`);
console.log(`Python files: ${result.pythonFiles?.length ?? 0}`);

// Build and format a report
const report = buildReport(result.findings, {
  tool: "SecureAI-Scan",
  version: "0.2.1",
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

**What languages does it support?**  
TypeScript, JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`) and Python (`.py`). All 19 rules run on TypeScript/JS. 11 of the most critical rules also run on Python — covering AI001–AI007, AI010, VEC001, VEC003, and MCP001.

**Does it work on LangChain / LlamaIndex / OpenAI SDK code?**  
Yes. The rules recognise patterns from `openai`, `anthropic`, `@langchain/openai`, `llama-index`, `google-generativeai`, LangChain Python, and more.

**What if I have too many findings to fix at once?**  
Use `--baseline` to create a snapshot. Future scans only show findings introduced after that point — fix the backlog at your own pace while blocking new issues in PRs.

**A finding is wrong — how do I suppress it?**  
Add a `// secureai-ignore RULE_ID: reason` comment on the line before the finding. The reason is required and is recorded in reports.

**Is there a way to ask questions without installing anything?**  
Yes. The **[SecureAI-Scan AI Security Advisor](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)** is a free Custom GPT on ChatGPT. Paste code, ask about any rule, or get an instant security review — no installation needed.

**Can I use it with Claude directly?**  
Yes. The included MCP server lets Claude Desktop call `scan_repository`, `explain_rule`, and `evaluate_prompt` as native tools. See the [MCP Server](#use-with-claude-mcp-server) section above.

**Can I add my own rules?**  
The `Rule` interface is public. Implement `{ id, title, severity, run(context) }` and pass it to the programmatic API.

**Does it replace a security audit?**  
No. It catches common patterns quickly and cheaply. A human security review is still valuable — and `secureai-scan threat-model` helps you prepare for it.

---

## Who This Is For

- **Development teams** shipping LLM features who want a pre-merge safety net
- **Security engineers** who need a fast, automated AI-risk inventory of a codebase
- **Founders and CTOs** who want evidence of security due diligence without a dedicated AppSec team
- **Python AI developers** building with LangChain, LlamaIndex, OpenAI SDK, or Anthropic SDK
- **Anyone building with MCP, RAG, or multi-agent architectures** — the attack surface is new and most scanners don't cover it yet

---

## Requirements

- Node.js 22 or later
- Scans TypeScript, JavaScript, and Python files (no Python installation required to run the scanner)

---

## License

MIT — [Akshay Kanthed](https://github.com/akanthed)

Issues and contributions welcome: [github.com/akanthed/SecureAI-Scan](https://github.com/akanthed/SecureAI-Scan)

---

**Try the free ChatGPT advisor:** [SecureAI-Scan AI Security Advisor](https://chatgpt.com/g/g-6a25141758188191a764020c1ab6a226-secureai-scan-ai-security-advisor)
