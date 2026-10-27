# Recall Corpus Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `npm run corpus`, a reproducible runner that scores MCP013/MCP014 recall (CVE-vulnerable commits plus harmless mutations) and precision (fix commits plus a clean-server set), and publish the method in `docs/Corpus.md`.

**Architecture:** JSON manifests pin repos at exact SHAs. `scripts/corpus-run.js` clones into a gitignored cache, applies `git apply` patches for mutations on a throwaway worktree, runs the built CLI with `--output <json>`, and compares findings to expectations. Shape mirrors `scripts/regression-scan.js`.

**Tech Stack:** Node ESM scripts (as in `scripts/`), `git`, the built CLI at `dist/index.js`, `node:test` for the runner test.

**Spec:** `docs/superpowers/specs/2026-10-27-recall-corpus-design.md`

## Global Constraints

- Scope stays LLM/MCP/RAG; no general SAST heuristics.
- No third-party source vendored: manifests plus patches only.
- `npm run build` before any test; tests import from `dist/`.
- After any rule change: `npm test` and `npm run regression` stay green, and every fixed false positive gets a fixture in `test-fixtures/safe/`.
- Any new code path in `src/cli.ts` needs a case in `test/cli.test.js` (this plan adds no CLI flags; the runner is a script).
- A recall fix must not loosen guards: membership tests count only against an allowlist; regexes count only if anchored or probing metacharacters.
- Do not commit, push, or post anything without the user asking.
- Cache dir `.corpus-cache/` is gitignored and not in `package.json` `files`.

## Review Focus

- Missing git history for a pinned SHA (shallow clone): runner must fetch the SHA explicitly and fail with a clear message, not scan the wrong tree.
- Patch no longer applies after the case is re-pinned: report "patch failed to apply" as a distinct error, never as a recall miss.
- CLI crash or missing report file: counts as ERROR, not as "clean", so a silent crash can't pass the precision side.
- Windows path separators in finding `file` fields: matching is on normalised `/` paths.
- Heuristic-tier findings (hidden unless `--paranoid`) must not count as a recall hit or a precision miss.

---

### Task 1: Manifest, checkout helpers, and unmutated CVE pairs

**Files:**
- Create: `corpus/cases.json`, `scripts/corpus/lib.js`, `scripts/corpus-run.js`
- Modify: `package.json` (script `"corpus": "npm run build && node scripts/corpus-run.js"`), `.gitignore` (`.corpus-cache/`)
- Test: `test/corpus-runner.test.js`

**Interfaces:**
- Produces in `lib.js`:
  - `checkoutAt(repoUrl: string, sha: string, cacheDir: string): string` returns a worktree path; fetches the exact SHA (`git fetch --depth 1 origin <sha>`).
  - `applyPatch(worktree: string, patchPath: string): void` uses `git apply`; throws `PatchError`.
  - `scanDir(dir: string): { ok: boolean; findings: {ruleId; file; line; evidence}[] }` runs `node dist/index.js scan <dir> --output <tmp.json>` and flattens `groups[].occurrences[]`; `ok` is false if no report file was written.
  - `hits(findings, {rule, file?}): number` counts `proven`/`likely` only, with `/`-normalised `file`.
- `cases.json` entry: `{ id, repo, vulnerableSha, fixSha, rule, file, tool }`, six entries copied from the table in `docs/RealWorldFindings.md` (Figma CVE-2025-53967, kubernetes CVE-2025-53355, package-docs CVE-2025-54073, kanban CVE-2025-53818, node-code-sandbox CVE-2025-53372, ios-simulator CVE-2025-52573). Resolve tags (`v0.6.2`, `2.4.9`, ...) and short SHAs to full 40-char SHAs with `git ls-remote`/`git rev-parse` and store only the full SHA.

- [ ] **Step 1: Write failing test.** In `test/corpus-runner.test.js`: `hits()` ignores `heuristic`, counts `proven` and `likely`, matches `a\\b.ts` against `a/b.ts`; `scanDir` on `test-fixtures/vulnerable/mcp_dynamic_command.ts`'s directory returns `ok: true` with `hits(..., {rule: "MCP013"}) >= 1`.
- [ ] **Step 2: Run** `node --test test/corpus-runner.test.js` after `npm run build`. Expected: FAIL (module missing).
- [ ] **Step 3: Implement `lib.js`** per the signatures above. Reuse the report-flattening logic from `scripts/regression-scan.js:140-154`.
- [ ] **Step 4: Implement `corpus-run.js` unmutated pass.** For each case: vulnerable must have `hits >= 1` for `rule`; fix must have `0`. Print one line per case; exit 1 on any miss or ERROR. Flag `--only <id>`.
- [ ] **Step 5: Run** `npm run corpus -- --only CVE-2025-52573`. Expected: vulnerable fires, fix clean. Then run all six; expected 6/6 and 6/6 per the documented results. If any differs from `docs/RealWorldFindings.md`, stop and report before continuing.
- [ ] **Step 6: Run** `node --test test/corpus-runner.test.js`. Expected: PASS.

### Task 2: Mutation patches (recall side) and mirror guards (precision side)

**Files:**
- Create: `corpus/mutations/<case-id>/<name>.patch`, a `mutations` array in each `cases.json` entry: `{ name, kind: "recall" | "guard", patch }`.
- Modify: `scripts/corpus-run.js`
- Test: `test/corpus-runner.test.js`

**Interfaces:**
- Consumes: `checkoutAt`, `applyPatch`, `scanDir`, `hits` from Task 1.
- Produces: per-mutation result `{ caseId, name, kind, pass, detail }`.

Mutation kinds per case (3-5 each, generated by reading the actual vulnerable file; a patch must keep the program semantically identical):
1. extra wrapper function around the sink
2. aliased import or renamed argument variable
3. added shell option or flag to the command string
4. sink moved into a helper in another file
5. template interpolation changed to string concatenation

`kind: "guard"` patches apply to the **fix** checkout and add a different-style real guard (allowlist via `Set.has`, anchored regex); these must stay at 0 hits. `kind: "recall"` patches apply to the **vulnerable** checkout and must keep `hits >= 1`.

- [ ] **Step 1: Write failing test.** Runner given a fake manifest (local git repo created in `os.tmpdir()` containing a copy of `test-fixtures/vulnerable/mcp_dynamic_command.ts`, with one recall patch and one broken patch) reports pass for the first and `PatchError` (not a recall miss) for the second.
- [ ] **Step 2: Run** the test. Expected: FAIL.
- [ ] **Step 3: Extend `corpus-run.js`** to apply each mutation on a fresh worktree copy, scan, and record the result. Broken patch gives `detail: "patch failed to apply"` and a non-zero exit.
- [ ] **Step 4: Write the patches** for all six cases; check each applies with `git apply --check`.
- [ ] **Step 5: Run** `npm run corpus`. Record every failing mutation. These are the recall gaps; they are the input to Task 5. Do not edit patches to make them pass.
- [ ] **Step 6: Run** `node --test test/corpus-runner.test.js`. Expected: PASS.

### Task 3: Clean set

**Files:**
- Create: `corpus/clean.json`
- Modify: `scripts/corpus-run.js`
- Test: `test/corpus-runner.test.js`

**Interfaces:**
- `clean.json` entry: `{ name, repo, sha }`; source list is `scripts/ecosystem-targets.txt` (25 entries). Each must produce `hits == 0` for `MCP013` and `MCP014` at default tier. Entries whose SHA cannot be resolved are dropped from the manifest and listed in `docs/Corpus.md`; do not guess.

- [ ] **Step 1: Write failing test.** Clean-set evaluation with a fake manifest: a directory containing the safe fixture `test-fixtures/safe/mcp_dynamic_command.ts` passes; the vulnerable one fails.
- [ ] **Step 2: Run** the test. Expected: FAIL.
- [ ] **Step 3: Implement** clean-set pass in `corpus-run.js`, checking only MCP013/MCP014 so unrelated rules don't fail it (that is `npm run regression`'s job).
- [ ] **Step 4: Run** `npm run corpus -- --clean-only`. Read every default-tier MCP013/MCP014 finding against its source line. If it is a false positive, treat it as a rule bug (Task 5), not a baseline entry.
- [ ] **Step 5: Run** the test. Expected: PASS.

### Task 4: Report table, `--json`, docs

**Files:**
- Modify: `scripts/corpus-run.js`
- Create: `docs/Corpus.md`
- Modify: `docs/RealWorldFindings.md` (link to `Corpus.md`), `README.md` (one link under Testing & benchmarking)
- Test: `test/corpus-runner.test.js`

**Interfaces:**
- `--json <path>` writes `{ generated, scanner: {name, version}, recall: {vulnerable: {passed, total}, mutations: {passed, total}}, precision: {fixed: {passed, total}, guards: {passed, total}, clean: {passed, total}}, cases: [...] }`. Version comes from `package.json`.
- `--scanner-cmd "<cmd {dir} {out}>"` replaces the scan command so another scanner that emits the same JSON shape can be scored. Document the shape in `docs/Corpus.md`.

- [ ] **Step 1: Write failing test** asserting the JSON shape and totals for the fake manifest, and that `--scanner-cmd` is honoured (use a stub command that writes a fixed report).
- [ ] **Step 2: Run** the test. Expected: FAIL.
- [ ] **Step 3: Implement** the printed table (recall row, precision row, per-case lines) and `--json`, `--scanner-cmd`.
- [ ] **Step 4: Write `docs/Corpus.md`**: method, mutation kinds, how to add a case, how to score another scanner, honest limits (six CVEs, MCP013/MCP014 only). Numbers in the doc come from an actual run, pasted from `--json`.
- [ ] **Step 5: Run** the test and `npm run corpus -- --json corpus/last-run.json`. Expected: PASS, file written.

### Task 5: Fix recall gaps the mutations expose (conditional)

**Files:**
- Modify: `src/scanner/rules/mcp-tool-arg-sink.ts`, `src/scanner/python-scanner.ts` (`checkMcpToolArgSink`) as needed
- Test: `test/mcp-tool-arg-sink.test.js`, `test-fixtures/vulnerable/`, `test-fixtures/safe/`, `test/corpus.test.js` (`EXPECTED_VULNERABLE`)

Applies only if Task 2 or 3 reported failures. One sub-cycle per distinct root cause, not per patch.

- [ ] **Step 1: For each failing mutation, write the smallest fixture** in `test-fixtures/vulnerable/` that reproduces the miss, and add a failing case in `test/mcp-tool-arg-sink.test.js`. For each clean-set false positive, add a fixture in `test-fixtures/safe/` naming the source repo/file.
- [ ] **Step 2: Run** `npm run build && node --test test/mcp-tool-arg-sink.test.js`. Expected: FAIL on the new case.
- [ ] **Step 3: Fix the rule at its root cause**, keeping the guard conventions in `CLAUDE.md` ("MCP tool-argument taint").
- [ ] **Step 4: Run** `npm test`, `npm run regression`, `npm run corpus`. Expected: all green; mutation recall improves; no new `proven`/`likely` in safe fixtures or the clean set. Read any new `regression` finding against its source before baselining.
- [ ] **Step 5: Re-run the CVE pairs** to confirm all six vulnerable still fire and all six fixes stay clean.

### Task 6: Release hygiene

**Files:**
- Modify: `CHANGELOG.md`, `docs/Corpus.md` (final numbers)
- Verify: `npm pack --dry-run --ignore-scripts` output

- [ ] **Step 1: Run** `npm pack --dry-run --ignore-scripts`. Expected: `corpus/`, `scripts/`, and `.corpus-cache/` do not appear in the tarball (nothing in `files` includes them).
- [ ] **Step 2: Run** `npm test`, `npm run regression`, `npm run corpus`. Expected: green; paste the final table into `docs/Corpus.md`.
- [ ] **Step 3: Add a CHANGELOG entry** describing the corpus and any rule fixes from Task 5.

---

## Self-review notes

- Spec coverage: manifest (T1), mutations and mirror guards (T2), clean set (T3), runner/JSON/other-scanner scoring/docs (T4), recall fixes (T5), runner test (T1-T4). Everything in the spec maps to a task.
- Names match across tasks: `checkoutAt`, `applyPatch`, `scanDir`, `hits`, `kind: "recall" | "guard"`.
- "Heuristic must not count" is pinned in `hits()` and tested in Task 1.
