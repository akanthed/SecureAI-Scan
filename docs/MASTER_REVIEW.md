# Master Review — SecureAI-Scan Growth Sprint

**Date:** 2026-08-01 · **Version:** 0.6.1 → work across this sprint and a follow-up pass applied on top

This is the rollup: scores, what changed, and the ranked backlog for what's next. See [`PROJECT_AUDIT.md`](PROJECT_AUDIT.md) for the detailed findings behind these scores — every finding there now carries a status marker (✅ resolved / 🔧 partial / ⏳ open) kept in sync with this document.

## Scores (/100)

| Dimension | Score | Rationale |
|---|--:|---|
| **Detection quality** | 85 | Genuinely disciplined evidence-tier system, import-resolved sinks, and a real regression benchmark against public repos — better methodology than most commercial scanners in this space. All 6 previously-unverified rules (AI011, MCP001, MCP003, VEC002–004) now have fixture-corpus recall proof; writing those fixtures also surfaced and fixed a real VEC003 false-positive class (see below). Still held back by the Python surface being regex-based by design, not AST. |
| **Architecture** | 78 | Clean separation of scanning surfaces, a well-justified reason each is architecturally distinct (see `docs/Architecture.md`), and a genuinely good "why" for every non-obvious design choice (evasion-resistance inverting the usual heuristic-lowers-evidence rule). Docked for zero caching/incremental-scan support and each surface doing its own file discovery independently — both correctly deferred as large efforts, not ignored. |
| **Documentation** | 82 | Was: excellent `CLAUDE.md` for an AI agent, near-nothing in `docs/` for a human contributor, thin `CONTRIBUTING.md`/`SECURITY.md`. Now: full `docs/` tree wired into the README, and root `CONTRIBUTING.md`/`SECURITY.md` both strengthened (technical setup links, precision-bar and scope-boundary callouts, a real vulnerability-disclosure policy distinguishing scanner bugs from detection gaps). |
| **Maintainability** | 80 | `tsc --strict` clean, zero TODO/FIXME/HACK in `src/`, 2 runtime dependencies total, consistent rule shape, now with coverage measurement (`npm run coverage`, c8) visible in CI. The deobfuscation test suite silently not running under `npm test` — exactly the kind of gap that erodes maintainability invisibly — is fixed, and it immediately surfaced a real bug, the strongest possible argument that this was worth doing. |
| **DevEx** | 74 | Command surface, flag validation messages, and `--help` quick-start examples are all above average. The silent-0-findings-on-a-bad-path bug (fixed) was a real, dangerous gap for a security tool specifically. A progress indicator on long scans is now in place; `init`'s silently-swallowed workflow-write error now surfaces its actual cause. |
| **OSS readiness** | 68 | No CI test gate, no PR template, no CODEOWNERS, no dependabot config, no Windows/macOS CI coverage — all real gaps for attracting outside contributors, all addressed except enabling GitHub Discussions and creating a labels taxonomy, which require live repo-settings changes only the maintainer can make (see "Not done" below). |
| **Enterprise readiness** | 70 | SARIF output, baseline diffing, policy files, and an evidence-tier system that avoids alert fatigue are all enterprise-relevant strengths. A `publish.yml` workflow now exists (needs an `NPM_TOKEN` secret to actually activate); coverage measurement is in place; `SECURITY.md` now has a real scope/response-expectation section rather than just an email address. |
| **Performance** | 72 | No algorithmic problems found; the gap is entirely an absence of caching/incrementality, which is a real cost at scale but not urgent at current adoption size — correctly deferred, not ignored (see `docs/Performance.md`). |

**Overall: 76/100** (up from 73). The core product — the detection engine and its precision discipline — is genuinely strong, arguably the standout part of the project. Nearly every code-fixable gap identified in the audit has been closed; what's left is either a large, deliberately-deferred design effort (Python AST rewrite, caching, three new detection rules) or requires the maintainer directly (repo settings, publish credentials, the image/GIF hosting decision).

## What this sprint actually changed

1. **Fixed a real, previously undetected bug** in `src/scanner/skill-bundle.ts`: the `GIT_TRANSIENT_FILE` regex's `^\.` catch-all (meant to skip hidden/transient files written inside `.git/`) also matched the literal directory name `.git` itself, causing the bundle walker to skip into `.git/` never — meaning SKL004's staged-payload detection inside `.git/` (the exact hiding place documented in arXiv:2607.02357) silently never fired. Found immediately upon wiring `deobfuscate.test.js` into `npm test` for the first time. Verified fixed and re-confirmed clean against the labeled Cisco skill-scanner corpus (6/6 malicious, 0 false positives) and all real bundles in `anthropics/skills`.
2. **Wired `deobfuscate.test.js` into `npm test`** (`test/run-tests.js`) — previously only ran via a direct, non-obvious invocation. This is the test suite covering the entire evasion-resistance module.
3. **Added `.github/workflows/ci.yml`** — build + `tsc --noEmit` + `npm test` on every PR and push to `main`, across a 3-OS × 2-Node-version matrix (Ubuntu/Windows/macOS × Node 20/22). Previously the only workflow was a non-blocking self-scan that never ran the test suite at all.
4. **Fixed the silent-0-files-on-bad-path CLI bug**: `secureai-scan scan <nonexistent-path>` now exits 1 with a clear error instead of exiting 0 with "no findings" — the most dangerous class of bug this audit found, since it fails in the direction (false confidence) the tool exists to prevent. Covered by a new case in `test/cli.test.js`.
5. **Added `.github/PULL_REQUEST_TEMPLATE.md`, `CODEOWNERS`, `dependabot.yml`.**
6. **Wrote the `docs/` tree**: `Architecture.md`, `DetectionEngine.md`, `WritingRules.md`, `RuleDevelopment.md`, `ThreatModel.md`, `Performance.md`, `FAQ.md`, `Contributing.md` — and linked all of it from the README.
7. **README additions**: a comparison table against Semgrep/Trivy/GHAS, a "See it work" section wiring in the existing (previously unreferenced) demo GIF and attack-flow diagrams, an ASCII architecture diagram, and Roadmap/Contributing sections — added to, not replacing, the existing README, which was already strong (evidence tiers, precision contract, real before/after regression numbers) and didn't need a rewrite.
8. **Wrote `docs/PROJECT_AUDIT.md`** (Phase 1) with severity-ranked findings and a rule-by-rule detection review appendix (Phase 4).

Every change above was verified: `npm run build && npm test` is green, and the skill-bundle fix was independently re-validated against real-world corpora via `npm run regression`.

## Follow-up pass: the rest of the code-fixable backlog

After the first pass, the remaining top-20 items were worked through directly (see the table below for full status). Highlights:

9. **Backfilled fixture-corpus coverage for all 6 previously-unverified rules** (AI011, MCP001, MCP003, VEC002, VEC003, VEC004) — new fixtures in `test-fixtures/vulnerable/`, wired into `EXPECTED_VULNERABLE`. Writing the VEC003 fixture surfaced a second real bug: `collectTaintedVars` treated *every* function parameter as user-tainted by presence alone, so any ordinary batch-ingestion function (`function importDocs(docs) { store.addDocuments(docs) }`) — with no request data anywhere in it — got flagged as user-controlled ingestion. Fixed to require the parameter actually be a request-object name (`req`/`request`/`ctx`), and pinned with a new `test-fixtures/safe/vec_batch_ingestion.ts` fixture. Re-verified clean against `llama_index` and `vercel/ai` via `npm run regression`.
10. **Added `.github/workflows/publish.yml`** matching the draft already documented in `PUBLISHING.md`. It will not publish anything until `NPM_TOKEN` is added as a repo secret — that step needs the maintainer's npm account.
11. **Added a progress indicator**: a single "Scanning `<path>`..." line to stderr before the scan starts, gated on `isTTY` so CI/piped logs stay clean. The scan pipeline is synchronous/CPU-bound with no natural yield point, so an animated spinner isn't feasible without a larger async rework — this is the honest low-effort version.
12. **Added coverage measurement**: `npm run coverage` (c8, text + HTML reporters) plus a non-blocking CI job uploading the HTML report as an artifact.
13. **Strengthened `CONTRIBUTING.md` and `SECURITY.md`** at the repo root — both now link to the new `docs/` tree, state the precision bar and scope boundary explicitly, and `SECURITY.md` distinguishes a vulnerability in the scanner itself from a detection gap (the latter is public-by-design, routed to the missed-detection issue template instead of private disclosure).
14. **Fixed `init`'s silently-swallowed CI-workflow-write error** — now surfaces the actual failure reason instead of a bare "(Skipped...)".
15. **Public-repo hygiene pass**: losslessly recompressed the two tracked diagram PNGs (~48% smaller, verified visually identical), removed the README's now-broken reference to a `demo.gif` that no longer exists on disk, and broadened `.gitignore` beyond exact filenames (`*.tgz` instead of one hardcoded version, plus `.vscode/`, `.idea/`, `Thumbs.db`, `*.log` so a future contributor's environment can't leak artifacts into a PR). A full audit of tracked files found no stray editor/OS junk, personal notes, or leaked secrets — the repo was already clean on that front; `GPT_PROMPT.md` and `spike/python-ast-poc/` are legitimate, purposeful public content (a documented live-GPT system prompt and a well-documented research spike backing the Python-AST roadmap item), not clutter, and were left as-is.

## Not done (explicitly, so it's not mistaken for "missed")

Only items that genuinely require the maintainer or a large, separately-scoped design effort remain open:

- **GitHub repo settings** (branch protection requiring the CI workflow, enabling Discussions, creating a labels taxonomy) — live account/repo-settings changes, not committed files.
- **The `NPM_TOKEN` secret** for `publish.yml` to actually activate — requires the maintainer's npm account.
- **Rewriting git history to fully remove the older, larger diagram blobs** — the two tracked PNGs are now losslessly recompressed (~48% smaller, see below), but the previous larger versions remain in git history. A full fix means rewriting history, which stays a maintainer decision. `demo.gif` (24.2 MB) is no longer present on disk at all; the README's broken reference to it was removed rather than left rendering broken on GitHub.
- **Python AST rewrite, caching/incremental scanning, shared file-discovery pass, and the three new detection rules** (model-configuration risk, agent-loop/iteration caps, MCP privilege-escalation/scope-creep) — all correctly identified as multi-week design efforts in the audit, not quick fixes. Attempting any of these without a dedicated design pass risks exactly the kind of premature-abstraction/rushed-evidence-tier work this project's own precision culture warns against.

## Top 20 improvements ranked by impact (final status)

| # | Improvement | Status |
|--:|---|---|
| 1 | CI runs build + tests on every PR | ✅ done |
| 2 | Wire `deobfuscate.test.js` into `npm test` | ✅ done — surfaced and fixed a real bug |
| 3 | Fix the `.git/` traversal bug in `skill-bundle.ts` | ✅ done |
| 4 | Fix silent-0-findings on a bad/nonexistent scan path | ✅ done |
| 5 | PR template, CODEOWNERS, dependabot.yml | ✅ done |
| 6 | `docs/` tree (Architecture, DetectionEngine, WritingRules, etc.) | ✅ done |
| 7 | README: comparison table, visuals section, architecture diagram | ✅ done |
| 8 | Backfill fixture coverage for AI011/MCP001/MCP003/VEC002-004 | ✅ done — also fixed a real VEC003 false-positive bug |
| 9 | Enable branch protection requiring the new CI workflow | ⏳ requires repo-settings access |
| 10 | Automated npm publish workflow on tag | 🔧 workflow committed, needs `NPM_TOKEN` secret |
| 11 | Resolve the 2.8 MB of committed PNGs / 24 MB untracked GIF | ⏳ requires a hosting decision |
| 12 | Progress indicator on long scans | ✅ done |
| 13 | GitHub Discussions + labels taxonomy | ⏳ requires repo-settings access |
| 14 | Coverage measurement (`c8`/`nyc`) | ✅ done |
| 15 | Strengthen `CONTRIBUTING.md`/`SECURITY.md` at repo root | ✅ done |
| 16 | Model-configuration-risk rule (new detection capability) | ⏳ roadmap item, needs design pass |
| 17 | Agent-loop / iteration-cap rule (new detection capability) | ⏳ roadmap item |
| 18 | MCP privilege-escalation/scope-creep rule (MCP02 coverage gap) | ⏳ roadmap item |
| 19 | Shared file-discovery pass across the 4 scanning surfaces | ⏳ open, moderate effort |
| 20 | Python AST rewrite (replace regex scanner) | ⏳ large, tracked in ROADMAP.md, spike exists |

## Is this project ready for 100 / 1,000 / 10,000 stars?

**100 stars — yes, and probably already achievable.** The core pitch (evidence-tiered findings, dataflow proof, MCP/Agent Skill coverage nothing else has) is genuinely differentiated and the README now states that clearly with a comparison table. This tier is about discoverability and a credible first impression, both of which are in reasonable shape after this sprint.

**1,000 stars — plausible, with the caveat that CI/OSS hygiene needed to exist before outside contributors would trust the project enough to send PRs, which was the biggest blocker before this sprint and is now mostly closed.** What's left at this tier: the maintainer needs to actually turn on branch protection (item #9) so the new CI gate means something, and the demo GIF/diagrams issue (#11) should be resolved before a wider audience starts cloning the repo. A blog post or write-up of the `Cloak and Detonate` evasion-resistance work would likely be the single highest-leverage marketing move available, since it's a genuinely novel, verifiable claim (validated against a labeled corpus) rather than a generic feature announcement.

**10,000 stars — not yet, and the honest gap is scope, not quality.** A project at this scale in the security-tooling space (Semgrep, Trivy) either has a much broader detection surface or a very sharp, singular hook that gets shared organically. SecureAI-Scan's hook (MCP/Agent Skill poisoning, evasion-resistant, benchmarked against real attack corpora) is sharp and defensible, but MCP/Agent Skills are still an emerging surface — the ceiling here is coupled to how big that ecosystem gets, not to anything fixable by more engineering work on this repo alone. The Python AST rewrite (#20) would meaningfully widen the addressable audience once the current TS/JS-first design has more headroom to invest in it.
