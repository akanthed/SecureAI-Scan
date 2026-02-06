# SecureAI-Scan

[![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan) [![license](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE) [![TypeScript](https://img.shields.io/badge/TypeScript-ready-blue.svg)](https://www.typescriptlang.org/)

**Catch dumb AI security mistakes before you ship.**

SecureAI-Scan is a repo-native CLI that scans your codebase for common LLM security foot-guns like prompt injection, PII exposure, and unsafe LLM usage. It runs locally and in CI with zero config.

> This is early, but useful. Expect rough edges and fast iteration.

## What It Catches
- Prompt injection risks (user input blended into prompts)
- PII or sensitive data sent to LLMs
- Unsafe LLM usage (for example, LLM calls before auth)

## Quick Start (Recommended)
```bash
npx secureai-scan scan .
```

No installation required. Works on all platforms, including Windows.

## Global Install (Optional)
```bash
npm install -g secureai-scan
npx secureai-scan scan .
```

Windows note: global installs may require PATH setup. `npx` is the easiest option.

## One-Command Usage
Want only AI/LLM rules?
```bash
npx secureai-scan scan . --only-ai
```

## Output Controls
Default behavior prints a summary and the top 3 issues to fix first.
```bash
npx secureai-scan scan . --limit 10
npx secureai-scan scan . --severity high
npx secureai-scan scan . --output report.md
npx secureai-scan scan . --output report.json
npx secureai-scan scan . --output report.html
```

## Workflow Commands
Use baseline mode to reduce repeat noise across runs.
```bash
npx secureai-scan scan . --baseline .secureai-baseline.json
npx secureai-scan scan . --baseline .secureai-baseline.json --output report.md
```

Target specific rules or get command help:
```bash
npx secureai-scan scan . --rules AI001,AI003
npx secureai-scan --help
npx secureai-scan scan --help
```

## All CLI Commands
```bash
# Scan
npx secureai-scan scan .
npx secureai-scan scan . --only-ai
npx secureai-scan scan . --rules AI001,AI003
npx secureai-scan scan . --severity high
npx secureai-scan scan . --limit 10
npx secureai-scan scan . --baseline .secureai-baseline.json
npx secureai-scan scan . --output report.md
npx secureai-scan scan . --output report.json
npx secureai-scan scan . --output report.html
npx secureai-scan scan . --debug

# Rule explanation
npx secureai-scan explain AI001

# Help
npx secureai-scan --help
npx secureai-scan scan --help
npx secureai-scan explain --help
```

## Example Output
```md
# SecureAI-Scan Report

## Summary

Total findings: 2

## Findings Table

| ID | Severity | Confidence | File | Line | Summary |
| --- | --- | --- | --- | --- | --- |
| AI003 | 🔴 CRITICAL | 0.80 | src/routes/chat.ts | 42 | LLM call occurs before auth checks. |
| AI004 | 🟠 HIGH | 0.80 | src/routes/chat.ts | 51 | Large user context sent directly to LLM. |

## Details

### AI003: LLM call before authentication

- Severity: 🔴 CRITICAL
- File: src/routes/chat.ts
- Line: 42
- Confidence: 0.80
- Summary: LLM call occurs before auth checks.

LLM call occurs in a request handler before authentication checks.

Recommendation: Ensure authentication/authorization runs before invoking LLMs in request handlers.
```

## Who This Is For
- Startup teams shipping LLM features fast
- Vibe coders who want guardrails without setup
- Developers who want quick, actionable feedback

## Who This Is Not For
- Compliance checklists or formal audits
- Fully-automated "security guarantees"
- Teams looking for cloud dashboards

## What This Does NOT Do
- It does not prove your app is secure.
- It does not replace code review or threat modeling.
- It does not run in the cloud or collect data.

## Disclaimer
This is an early-stage tool. It will miss things. Use it as a helpful signal, not a final security verdict.

## Why It's Useful
You do not need a huge security program to avoid obvious mistakes. This tool gives you a fast, local safety net so you can move fast without stepping on the same rakes.
