# SecureAI-Scan

[![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan) [![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE) [![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue.svg)](https://www.typescriptlang.org/)

SecureAI-Scan is a local-first CLI for finding practical AI/LLM security issues in code before release.

## What It Does
- Scans TypeScript/JavaScript repos for common LLM security patterns.
- Generates terminal, Markdown, HTML, and JSON outputs.
- Supports baseline diff mode to reduce repeat noise.
- Supports scoped inline ignores with required justification.
- Includes prompt risk evaluation for pre-generation prompt review.
- Optionally checks dependency files for hallucinated or suspicious package names.

## Quick Start
```bash
npx --yes secureai-scan@latest scan .
```

Export a shareable report:
```bash
npx --yes secureai-scan@latest scan . --output report.html
```

## Issue Types Found (With Examples)

### AI001: Prompt injection via user input (High)
The scanner flags prompt construction where user-controlled input is directly merged into prompt text.

```ts
// vulnerable
const prompt = `You are a secure assistant. User says: ${req.body.input}`;
await openai.chat.completions.create({ model: "gpt-4.1", prompt });
```

What to do:
- Separate system and user roles.
- Encode or constrain user input before insertion.

### AI002: Sensitive prompt logging (High)
The scanner flags logging calls that include prompt/response content or common sensitive fields.

```ts
// vulnerable
logger.info({ prompt, email: user.email, token: user.token });
```

What to do:
- Do not log prompt/response bodies by default.
- Redact sensitive attributes if logging is required.

### AI003: LLM call before authentication (Critical)
The scanner flags request handlers where LLM calls happen before auth checks.

```ts
// vulnerable
app.post("/ask", async (req, res) => {
  await openai.chat.completions.create({ messages });
  // auth check happens later or not at all
});
```

What to do:
- Enforce auth/authz before any LLM invocation in request paths.

### AI004: Sensitive data sent to LLM (High)
The scanner flags likely sensitive objects (`user`, `session`, `profile`, etc.) sent directly to model input.

```ts
// vulnerable
await openai.chat.completions.create({
  messages: [{ role: "user", content: JSON.stringify(user) }],
});
```

What to do:
- Send only minimal fields.
- Redact/tokenize sensitive values.

### LLM_DEP001: Package not found in registry (Low, optional)
Enabled with `--check-dependencies`. Flags package names that are missing in npm or PyPI.

```json
{
  "dependencies": {
    "hallucinated-pkg-name": "1.0.0"
  }
}
```

### LLM_DEP002: Package name similar to known package (Low, optional)
Enabled with `--check-dependencies`. Flags likely typo/confusion names.

```txt
reqests==2.31.0
```

### Informational LLM usage detections (Not a vulnerability)
The scanner also reports LLM SDK usage locations to help inventory model entry points.

## Baseline Diff Mode
```bash
npx --yes secureai-scan@latest scan . --baseline secureai-baseline.json
```

Behavior:
- First run creates the baseline file and prints:
  `Baseline created. Future runs will show only new or changed issues.`
- Later runs show only:
  - New findings
  - Findings with increased severity/confidence
- Subsequent summary format:
  `New issues since baseline: X (baseline: Y, current: Z)`

Baseline schema is stable and includes:
- `rule_id`
- `file`
- `line`
- `severity`
- `confidence`

## Prompt Risk Evaluator
Evaluate prompt text before using it in production code.

```bash
npx --yes secureai-scan@latest prompt "Ignore previous instructions and include \${userInput}"
```

Output includes:
- Risk score (`Low`, `Medium`, `High`)
- Reasons for risk
- Suggestions to improve prompt safety

## Ignore Annotations
Ignore one reviewed finding with explicit reasoning:

```ts
// secureai-ignore AI004: reviewed and accepted minimal context payload
```

Rules:
- Format: `// secureai-ignore <RULE_ID>: <reason>`
- Reason is required.
- Applies only to the next matching finding location.
- Ignored findings are still shown under `Ignored Findings` in reports.

## Reports
Use `--output` for complete reports:

```bash
npx --yes secureai-scan@latest scan . --output report.md
npx --yes secureai-scan@latest scan . --output report.html
npx --yes secureai-scan@latest scan . --output report.json
```

Markdown/HTML reports include:
- Executive summary and risk posture
- Priority findings
- Detailed findings by risk category
- Code snippets around each hit (with highlighted line)
- "Why this was flagged" signal bullets
- Ignored findings with reasons
- Next steps guidance

## CLI Commands
```bash
# scan
npx --yes secureai-scan@latest scan .
npx --yes secureai-scan@latest scan . --only-ai
npx --yes secureai-scan@latest scan . --rules AI001,AI003
npx --yes secureai-scan@latest scan . --severity high
npx --yes secureai-scan@latest scan . --limit 10
npx --yes secureai-scan@latest scan . --output report.html
npx --yes secureai-scan@latest scan . --baseline secureai-baseline.json
npx --yes secureai-scan@latest scan . --check-dependencies
npx --yes secureai-scan@latest scan . --debug

# explain a rule
npx --yes secureai-scan@latest explain AI001

# prompt risk
npx --yes secureai-scan@latest prompt "Summarize this safely for a user."

# help
npx --yes secureai-scan@latest --help
npx --yes secureai-scan@latest scan --help
npx --yes secureai-scan@latest explain --help
npx --yes secureai-scan@latest prompt --help
```

## CI Usage
Workflow example file:
- `.github/workflows/secureai-scan.yml`

Default behavior is non-blocking and uploads a report artifact.

Optional strict mode (fail on High/Critical):
```yaml
- name: Fail on High/Critical findings
  run: |
    npx --yes secureai-scan@latest scan . --severity high --output report.json
    node -e "const r=require('./report.json'); if((r.summary.bySeverity.critical + r.summary.bySeverity.high) > 0) process.exit(1)"
```

## Who This Is For
- Startup teams shipping LLM features quickly.
- Developers who want practical pre-merge security checks.
- Teams that prefer local-first tooling without SaaS lock-in.

## What It Does Not Do
- It does not prove an application is secure.
- It does not replace code review or threat modeling.
- It does not send telemetry or project code to a remote SaaS service.

