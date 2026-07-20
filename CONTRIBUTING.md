# Contributing

Thanks for wanting to help. This project is early and moving fast, so small, focused contributions are the most helpful.

## What to Work On
- Detection rules with clear, testable patterns
- Fixes to reduce false positives
- Docs improvements and examples

## How to Contribute
1. Fork the repo
2. Create a branch with a clear name
3. Keep changes small and focused
4. Add or update test fixtures if relevant
5. Open a PR with a short description and before/after behavior

## Code Style
- Keep it readable
- Prefer simple logic over cleverness
- Keep rules isolated and testable

## Package Advisories (DEP003)
The curated advisory list lives in `src/scanner/advisories.ts` and produces `proven` findings, so the inclusion bar is high:
- Only add a package with a **public incident report or CVE** as the reference — never on suspicion
- Include the affected version range when the source documents one
- `kind: "malicious"` is for documented backdoors/malware (reported critical); `kind: "vulnerable"` is for critical CVEs (reported high)
- PRs adding advisories should link the reference and add a case to `test/dependency-guard.test.js`

## Reporting Issues
For security issues, please follow `SECURITY.md`.
