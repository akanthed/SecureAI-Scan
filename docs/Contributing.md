# Contributing (developer setup)

This is the technical companion to [`CONTRIBUTING.md`](../CONTRIBUTING.md) at the repo root — that file covers workflow expectations (small focused PRs, advisory bar); this one covers getting a working dev environment and understanding where things live.

## Setup

```bash
git clone https://github.com/akanthed/SecureAI-Scan.git
cd SecureAI-Scan
npm install
npm run build     # clean + tsc compile to dist/
npm test          # build, then run test/run-tests.js
```

There is no separate lint script — `tsc` in strict mode (`tsconfig.json`) is the only static check. Always `npm run build` before running tests: tests import from `dist/`, not `src/`.

```bash
npm run dev        # build + run dist/index.js
npm run regression # build, then scan real public repos (see docs/RuleDevelopment.md)
node --test test/corpus.test.js   # run a single test file directly, after building
```

## Where things live

- Detection logic: `src/scanner/rules/*.ts` (TS/JS AST), `src/scanner/python-ast.ts` + `src/scanner/python-scanner.ts` (Python AST), `src/scanner/mcp-config-scanner.ts` + `src/scanner/skill-scanner.ts` (config/content), `src/scanner/dependency-guard.ts` (advisories). See [Architecture.md](Architecture.md).
- CLI wiring: `src/cli.ts`. Any change here needs a corresponding case in `test/cli.test.js` — it's the only test file that exercises the real built binary via `execFileSync` rather than calling scanner functions directly, so a flag-wiring bug (a dropped parser argument, a flag that silently no-ops) has no other test that would catch it. This has happened once already.
- Test corpus: `test-fixtures/vulnerable/` and `test-fixtures/safe/`, enforced by `test/corpus.test.js`.
- Documentation you're reading now: `docs/`. Auto-generated/per-project docs (`THREAT_MODEL.md`, the AI-BOM) are separate — see [ThreatModel.md](ThreatModel.md) for the distinction.

## Before opening a PR

1. `npm run build && npm test` — must be clean.
2. If you touched detection logic (a rule file, `tool-poisoning-checks.ts`, `python-scanner.ts`, `confidence.ts`): `npm run regression`, and triage every `proven`/`likely` finding it prints (see [RuleDevelopment.md](RuleDevelopment.md)).
3. If you touched `src/cli.ts`: add or update a case in `test/cli.test.js`.
4. If you added a rule: catalog entry (`catalog.ts`) + explainer entry (`explainer.ts`) + fixtures in both `test-fixtures/vulnerable/` and `test-fixtures/safe/` (see [WritingRules.md](WritingRules.md)).

## Package advisories (`DEP003`)

Covered in full in the root [`CONTRIBUTING.md`](../CONTRIBUTING.md) — repeating the key constraint here since it's the easiest one to get wrong: only add a package with a **public incident report or CVE** as the reference, never on suspicion, and add a case to `test/dependency-guard.test.js` proving both the vulnerable version is flagged and the patched version clears.

## Questions

Open a [GitHub Discussion](https://github.com/akanthed/SecureAI-Scan/discussions) for anything that isn't a bug report or a concrete feature request — the issue templates under `.github/ISSUE_TEMPLATE/` cover bug reports, false positives, and missed detections specifically.
