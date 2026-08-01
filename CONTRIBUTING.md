# Contributing

Thanks for wanting to help. This project is early and moving fast, so small, focused contributions are the most helpful.

For the technical setup (build/test commands, where detection logic lives, the pre-PR checklist), see [`docs/Contributing.md`](docs/Contributing.md). This file is the short version.

## What to Work On
- Detection rules with clear, testable patterns
- Fixes to reduce false positives
- Docs improvements and examples

## How to Contribute
1. Fork the repo
2. Create a branch with a clear name
3. Keep changes small and focused
4. Add or update test fixtures if relevant
5. `npm run build && npm test` must pass; if you touched detection logic, also run `npm run regression` and triage every finding it prints (see [`docs/RuleDevelopment.md`](docs/RuleDevelopment.md))
6. Open a PR using the template — it has a checklist for rule changes and CLI changes specifically

## Code Style
- Keep it readable
- Prefer simple logic over cleverness
- Keep rules isolated and testable

## The precision bar

This project's entire value proposition is zero false positives by default (see the README's "precision contract"). Any change to detection logic that introduces a new false positive, or that doesn't fix one found during the work, will be asked to add a `test-fixtures/safe/` fixture before merging. See [`docs/WritingRules.md`](docs/WritingRules.md) and [`docs/DetectionEngine.md`](docs/DetectionEngine.md) for what's expected.

**Scope stays fixed to LLM/MCP/RAG-related risk.** A PR adding general-purpose SAST or secret-scanning heuristics (SQL injection, XSS, path traversal with no LLM/MCP context) will be redirected, even for a real incident — see [`docs/ThreatModel.md`](docs/ThreatModel.md) for why and what the right fix looks like instead (usually a `DEP003` advisory).

## Package Advisories (DEP003)
The curated advisory list lives in `src/scanner/advisories.ts` and produces `proven` findings, so the inclusion bar is high:
- Only add a package with a **public incident report or CVE** as the reference — never on suspicion
- Include the affected version range when the source documents one
- `kind: "malicious"` is for documented backdoors/malware (reported critical); `kind: "vulnerable"` is for critical CVEs (reported high)
- PRs adding advisories should link the reference and add a case to `test/dependency-guard.test.js`

## Reporting Issues
For security issues, please follow `SECURITY.md`.
