# SecureAI-Scan — Project Audit

**Date:** 2026-08-01 · **Version audited:** 0.6.1 · **Scope:** architecture, code quality, CLI/DevEx, detection engine, rule organization, testing, docs, GitHub setup, release process, performance.

This audit is a snapshot, not a verdict on the team. The scanner's core detection philosophy (evidence tiers, import-resolved sinks, a real precision-gate corpus) is unusually disciplined for a project this age — most of what follows is about closing gaps between that strong core and the surrounding project scaffolding (CI, docs, GitHub hygiene) that a first-time visitor judges the project by before ever reading a line of rule code.

Each finding: **Severity** (Critical/High/Medium/Low) · **Effort** (S/M/L) · **Why it matters**.

**Status key used below:** ✅ Resolved (fixed this sprint, see `docs/MASTER_REVIEW.md` for the commit-level writeup) · 🔧 Partially resolved (code landed, needs an action only the maintainer can take) · ⏳ Open (tracked, not started).

---

## 1. Critical

### 1.1 `npm test` does not run in CI at all — ✅ Resolved
**Effort: S**
`.github/workflows/secureai-scan.yml` is a self-scan/dogfood workflow — it runs `npx secureai-scan@latest scan .` against the repo and uploads a report, non-blocking (`|| true`). There is no workflow that runs `npm test`, `npm run build`, or `tsc --noEmit` on PRs. A PR can merge with a broken build or a failing test and nothing will catch it. This is the single highest-leverage fix in the whole audit — every other quality claim in this document (98%+ of the "hard requirements" in CLAUDE.md) is unenforced without it.

### 1.2 `deobfuscate.test.js` isn't wired into `npm test` — ✅ Resolved
**Effort: S**
`test/run-tests.js` imports 10 of the 11 test files as ESM side effects; `deobfuscate.test.js` (263 lines, covering the evasion-resistance module described as a deliberate, hard-won design decision in CLAUDE.md) is not among them. It only runs via a direct `node --test test/deobfuscate.test.js` invocation. Combined with 1.1, this means the evasion-resistance logic — the part of the codebase explicitly built to defeat published jailbreak/scanner-evasion techniques — currently has **zero** automated verification in any run path a contributor or CI would naturally trigger.

Wiring it in immediately validated the concern: it surfaced a real, previously-shipping bug in `skill-bundle.ts`'s `.git/` traversal (SKL004 never actually detected payloads staged there). See `docs/MASTER_REVIEW.md` for the fix.

### 1.3 Six registered rules have no fixture-corpus coverage — ✅ Resolved
**Effort: M**
AI011, MCP001, MCP003, VEC002, VEC003, VEC004 are registered in `rules/index.ts` and shipped, but have no `test-fixtures/vulnerable/` file and no `EXPECTED_VULNERABLE` entry in `test/corpus.test.js` proving they still fire. Several (AI006, AI007, AI008, AI009) are exercised only via inline strings in `test/new-ai-rules.test.js`, not the fixture corpus that the project's own CLAUDE.md calls the "precision gate." A rule with no corpus fixture can silently regress to zero findings (as literally happened once already, per CLAUDE.md's own account of the AI002/AI007/AI008 false-positive fixes) with nothing failing red. This directly undermines hard requirement #1 in CLAUDE.md ("zero tolerance for false positives... the corpus alone is not sufficient" — true, but right now it's also not complete).

Fixtures added for all six (`test-fixtures/vulnerable/multiagent_trust.ts`, `mcp_tool_metadata.ts`, `mcp_tool_result.ts`, `vec_unbounded_search.ts`, `vec_user_ingestion.ts`, `vec_ingest_no_namespace.ts`), wired into `EXPECTED_VULNERABLE`. Writing the VEC003 fixture surfaced a second real bug in the same rule — `collectTaintedVars` treated *every* function parameter as user-tainted by presence alone, flagging any ordinary batch-ingestion function (`function importDocs(docs) { store.addDocuments(docs) }`) with no actual request-data link. Fixed to require the parameter name to actually look like a request object (`req`/`request`/`ctx`), and pinned with a new `test-fixtures/safe/vec_batch_ingestion.ts` fixture.

---

## 2. High

### 2.1 No PR template, CODEOWNERS, or Dependabot config — ✅ Resolved
**Effort: S**
`.github/` has issue templates (good — bug report, false positive, missed detection are well-chosen categories for this project) but no `PULL_REQUEST_TEMPLATE.md`, no `CODEOWNERS`, no `dependabot.yml`. For a security-tooling project specifically, an unmonitored dependency tree is an ironic look — the tool itself flags dependency risk (DEP001–003) but doesn't dogfood dependency update automation on itself.

### 2.2 No automated npm publish workflow — 🔧 Partially resolved
**Effort: M**
`PUBLISHING.md` documents both a manual flow (currently what's used) and a `publish.yml` GitHub Actions workflow triggered on `v*` tags — but that workflow file was never actually committed. Manual publishing is a single-point-of-failure (one person's local npm token/2FA) and non-reproducible (no guarantee the published tarball matches what CI built and tested).

`.github/workflows/publish.yml` is now committed, matching the draft that was already in `PUBLISHING.md`. It will not actually publish anything until an `NPM_TOKEN` secret is added in repo settings — that step requires the maintainer's npm account and can't be done from a PR.

### 2.3 Bad/nonexistent scan paths silently report "0 findings," not an error — ✅ Resolved
**Effort: S**
Verified: `secureai-scan scan /nonexistent/path` exits **0** with `0 files · 0.0s` and `✓ No findings at the current evidence level.` A typo'd path is indistinguishable from a genuinely clean 40-file repo. For a security tool, "clean" must never be reachable by accident — this is the most dangerous class of UX bug this audit found, because it fails silently in the exact direction (false confidence) the tool exists to prevent. Should be a distinct message + non-zero exit (or at minimum a loud warning) when 0 files are discovered.

### 2.4 2.8 MB of PNGs committed to git history for content excluded from the npm tarball — ⏳ Open (needs a maintainer decision)
**Effort: S**
`mcp-attack-diagram.png` (1.36 MB) and `rag-poisoning-diagram.png` (1.48 MB) are tracked in git. They're correctly excluded from the npm package via `.npmignore`, so they don't bloat installs — but they permanently bloat `git clone` size and repo history for every future contributor. `demo.gif` (24.2 MB, currently untracked) would be far worse if committed as-is. Large binary assets like this belong either compressed, hosted externally (GitHub release assets, a CDN, or the repo's own GitHub Pages `docs/`), or added via Git LFS — not committed raw to the default branch. Left open deliberately: resolving it means either rewriting recent git history or standing up external hosting, both decisions for the maintainer, not something to do silently.

### 2.5 CI runs on Ubuntu only, no Node version matrix — ✅ Resolved
**Effort: S**
The one existing workflow runs on `ubuntu-latest` / Node 20 only. Given `engines.node >= 20` and the project's Python-regex scanner and TS AST scanner both do path/glob handling that historically has Windows-vs-POSIX edge cases (path separators, case sensitivity), shipping with zero Windows/macOS CI coverage is a real gap — a contributor on Windows (as this very session is) has no CI signal that their environment matches what maintainers test. `ci.yml` now runs on a 3-OS × 2-Node-version matrix; the Windows leg would have caught the `.git/`-traversal bug (see 1.2) immediately.

### 2.6 No test/build/lint gate blocks merges to `main` — 🔧 Partially resolved
**Effort: S** (config only, once 1.1 exists)
Related to 1.1 but distinct: even after a CI test workflow exists, without branch protection requiring it to pass, it's advisory only. `ci.yml` now exists (1.1); turning on branch protection to require it is a repo-settings change, not code, and still needs to be done directly by the maintainer.

---

## 3. Medium

### 3.1 `docs/` is a single landing-page HTML file, not documentation — ✅ Resolved
**Effort: L**
`docs/index.html` (30 KB) is a marketing/landing page. There is no `docs/Architecture.md`, `DetectionEngine.md`, `WritingRules.md`, etc. Everything a new contributor needs to understand the codebase currently lives entirely in `CLAUDE.md` (16 KB, genuinely excellent, but written for an AI coding agent, not indexed/discoverable the way a human contributor browsing GitHub would expect `docs/` to be). Addressed in Phase 5 of this sprint.

### 3.2 `CONTRIBUTING.md` and `SECURITY.md` are thin stubs — ✅ Resolved
**Effort: M**
`CONTRIBUTING.md` (30 lines) covers workflow but not the actual architecture knowledge a contributor needs (rule shape, evidence tiers, where to add fixtures) — that's all in CLAUDE.md instead, which is Claude-Code-specific framing and not obviously the "start here" doc a human contributor would find. `SECURITY.md` (16 lines) has no PGP key, no disclosure timeline commitment, no supported-versions table — reasonable for project size but worth strengthening given the project's own subject matter is security. Both now link to `docs/Contributing.md`, and `SECURITY.md` clarifies the distinction between a vulnerability in the scanner itself vs. a detection gap (the latter goes through the missed-detection issue template, not private disclosure).

### 3.3 No coverage measurement — ✅ Resolved
**Effort: S**
No `c8`/`nyc`/`istanbul` configured. 1,431 lines of test code exist across 11 files (reasonable volume) but there's no visibility into which rule branches, CLI flag combinations, or error paths are actually exercised. Given hard requirement #4 in CLAUDE.md calls out that CLI-flag-wiring bugs specifically evaded detection once already, coverage reporting would make that class of gap visible before it recurs. `npm run coverage` (c8, text + HTML reporters) is now wired in, plus a non-blocking CI job that uploads the HTML report as an artifact on every PR.

### 3.4 Scanner has no caching or incremental-scan support — ⏳ Open (large effort, correctly deferred)
**Effort: L**
`src/scanner/project.ts` rebuilds the full `ts-morph` Project from scratch on every invocation; `--baseline` diffs *findings*, not files. Python scanning, MCP config scanning, and skill scanning each independently re-walk the filesystem rather than sharing one file-discovery pass. Not algorithmically pathological (no O(n²) found), but on large monorepos this means every CI run and every local re-scan pays full cost. Not urgent at current adoption scale, but worth a design note before it becomes a support complaint.

### 3.5 No progress indicator on long scans — ✅ Resolved
**Effort: S**
Nothing prints between invocation and the final report on a large repo — a scan that takes 10+ seconds on a big monorepo looks hung. A single "Scanning `<path>`..." line now prints to stderr before the (synchronous, CPU-bound) scan starts, gated on `process.stderr.isTTY` so CI/piped logs aren't cluttered. An animated spinner isn't feasible without making the scan pipeline asynchronous, which is out of scope here.

### 3.6 `init`'s CI-workflow-write failure is swallowed silently — ✅ Resolved
**Effort: S**
`src/cli.ts`'s `init` command had a bare `catch {}` around the GitHub Actions workflow scaffold write, surfaced only as "(Skipped...)" with no reason. Now includes the actual error message.

### 3.7 devDependencies include a tree-sitter Python toolchain used only by an unshipped spike
**Effort: S**
`tree-sitter-python` and `web-tree-sitter` are devDependencies feeding only `spike/python-ast-poc/`, not `src/`. They add real install weight (`npm ci`) to every contributor and CI run for code that isn't part of the product. Either promote the spike to a real replacement for the regex-based Python scanner (see 4.1 below) or drop the dependency until that work starts.

---

## 4. Low

### 4.1 Python scanner is regex/line-based, not AST — CLAUDE.md itself flags this as more false-positive-prone
**Effort: XL (tracked separately, not a quick fix)**
Not a bug, but worth stating plainly in the audit: the TS/JS engine's core value proposition (import-resolved sinks, traced dataflow) doesn't apply to the Python surface, which is inherently a weaker detection story. The `spike/` directory suggests this is already recognized internally. Flagging here so it's visible in the roadmap ranking rather than assumed-in-progress.

### 4.2 `GPT_PROMPT.md` tracked at repo root
**Effort: S**
An 11 KB file tracked in git, excluded from npm via `.npmignore` but visible to anyone browsing the repo on GitHub. Not harmful, but unclear to an outside contributor what it's for — either document its purpose inline or move it under an internal-tooling directory that signals "not part of the public docs."

### 4.3 `report.html` / `report.md` present on disk (correctly gitignored)
**Effort: None** — verified these are `!!`-ignored, not tracked. No action needed; noted only because they appear in `git status`-adjacent tooling and could look like an oversight at a glance.

---

## Package/dependency hygiene — clean

For completeness: `npm pack --dry-run` produces a lean 127.8 kB / 55-file tarball (dist + mcp-server + skills + README + LICENSE only). Runtime dependencies are exactly two (`commander`, `ts-morph`), both genuinely used. `tsc --noEmit` is clean under `strict: true`. Zero `TODO`/`FIXME`/`HACK` comments in `src/`. This is genuinely good hygiene and shouldn't be touched without reason — noted so Phase-2-and-later work doesn't "fix" something that isn't broken.

---

## Priority order for implementation (this sprint)

1. CI workflow: build + `tsc --noEmit` + `npm test` (**including** deobfuscate.test.js) on every PR — fixes 1.1 and 1.2 together (S effort, unblocks trusting every other change made this sprint).
2. Fix silent-0-files-on-bad-path CLI bug (2.3) — S effort, highest safety impact.
3. Add PR template, CODEOWNERS, dependabot.yml (2.1) — S effort, standard OSS hygiene.
4. Backfill fixture-corpus coverage for the 6 uncovered rules (1.3) — M effort, directly serves the project's own stated precision contract.
5. README rewrite (Phase 2 of this sprint, tracked separately).
6. docs/ tree (Phase 5), GitHub Actions Node matrix (2.5), progress indicator (3.5), remaining items as capacity allows.

Items 3.4 (caching/incremental scan) and 4.1 (Python AST rewrite) are correctly large, multi-week efforts — flagged for the roadmap, not this sprint.

---

## Appendix: rule-by-rule review

Column legend: **Recall proof** = does a `test-fixtures/vulnerable/` fixture prove this rule still fires (checked into `EXPECTED_VULNERABLE`)? **Precision proof** = is there a `safe/` fixture pinning a known near-miss?

| Rule | Catches | Main false-positive risk if evidence discipline slips | Recall proof | Precision proof |
|---|---|---|---|---|
| AI001 | User input traced into a system/developer prompt | Losing import-resolution on the sink (would flag any string concat near a prompt-shaped variable) | ✅ | ✅ |
| AI002 | Prompt/secret content written to logs, LLM-adjacent files only | Matching "token"/"secret" as bare identifiers (already fixed once — OAuth `token_endpoint` fields) | ✅ | ✅ |
| AI003 | LLM call in a request handler with no auth check first | Any handler shape without a resolved LLM sink | ✅ | ✅ |
| AI004 | Whole user/session object serialized into a prompt | Flagging deliberate field-picking as if it were the whole object | ✅ | ✅ |
| AI005 | LLM output reaching eval/exec/SQL/HTML sinks | Shared method names across domains (`"query"` as both SQL sink and Claude Agent SDK call — a real bug found in the `vercel/ai` regression run) | ✅ | ✅ |
| AI006 | High-impact tools exposed with no approval gate | Naming heuristics ("delete", "pay") without call-site context | inline in `new-ai-rules.test.js`, no `test-fixtures/` file | — |
| AI007 | Retrieved RAG content interpolated into privileged prompts | `chunks`-style streaming variable names read as unambiguous RAG evidence (real, fixed false positive) | inline + `false-positive-regressions.test.js` | ✅ (regression pair) |
| AI008 | Secrets embedded in system prompt text | Raw substring search on "secret"/"token" in narrative prose (real, fixed false positive) | inline in `new-ai-rules.test.js` | ✅ |
| AI009 | Unbounded user input / missing token limits | Any large-input handling flagged without an LLM-sink link | inline in `new-ai-rules.test.js` | — |
| AI010 | Fetched external content flows into prompts | Same import-resolution risk as AI001 | `false-positive-regressions.test.js` | ✅ |
| AI011 | Agent output elevated to system-role downstream | No dedicated fixture at all — **weakest-verified rule in the corpus today** | ❌ none | ❌ none |
| AI012 | LLM output parsed without schema validation | Only a negative (must-not-fire) assertion exists — recall is currently unproven | ❌ none | ✅ (negative only) |
| MCP001 | MCP tool metadata reaches the system prompt unvalidated | The exact class that caused the Python `description=`/"system prompt" false positive in `llama_index` | ❌ none | — |
| MCP002 | MCP server URL built from user input | Bare `"params."` matching (real, fixed false positive — a URL-scheme validator got flagged) | ✅ | ✅ |
| MCP003 | MCP tool results elevated to system-role | No dedicated fixture | ❌ none | — |
| MCP004–006 | Unpinned `npx -y`, inline secrets, plaintext HTTP in MCP config | Parsed JSON facts, not pattern matches — inherently low FP risk | ✅ | ✅ |
| MCP007–009 | Invisible Unicode / injection phrases / shadowing in MCP tool descriptions | Shared logic with SKL001–003; validated against the Cisco labeled corpus (6/6, 0 FP) | ✅ | ✅ |
| MCP010 | MCP stdio command/args built from request data (RCE) | Same `REQUEST_SOURCES` bare-`params` risk as MCP002 (also fixed) | ✅ | ✅ |
| SKL001–005 | Invisible Unicode / injection phrasing / shadowing / staged payloads / credential-exfil in Agent Skill bundles | Extensively adversarially tested — see README's "Evasion resistance" section; SKL004's `.git/` traversal had a real bug (fixed during this sprint, see commit history) | ✅ | ✅ |
| VEC001 | Vector search without tenant/user filter | Flags generic retriever library code with nothing to filter (documented inherent limit in `llama_index`, not a bug) | `false-positive-regressions.test.js` | ✅ |
| VEC002 | Unbounded/user-controlled search limit | No dedicated fixture | ❌ none | — |
| VEC003 | User content ingested into a shared vector store | No dedicated fixture | ❌ none | — |
| VEC004 | Ingestion without tenant/namespace tagging | No dedicated fixture | ❌ none | — |
| DEP001–003 | Registry-missing, typosquat, and known-malicious/CVE dependencies | Version-range comparison bugs (real, fixed — `affectedVersions` was once display-only, never actually compared) | `dependency-guard.test.js`, both directions | ✅ |

**Missing detections worth scoping for the roadmap, not this sprint:**
- Model-configuration risk (temperature/safety-setting misconfiguration, missing content-filter flags on provider SDK calls) — currently no rule covers model *configuration* as distinct from prompt *content*.
- Agent-loop risk (unbounded recursive tool-calling / no iteration cap on agentic loops) — adjacent to AI009 (unbounded input) but distinct; AI009 doesn't currently cover iteration counts.
- Excessive permissions on MCP server *scopes* (as opposed to tool poisoning) — OWASP MCP Top 10's MCP02 "Privilege Escalation via Scope Creep" has no dedicated rule yet, only appears as a framework-mapping target with partial coverage via MCP004–006.

These three are genuinely new detection capabilities, not false-positive fixes — each needs its own design pass per [`docs/WritingRules.md`](WritingRules.md), not a quick patch.
