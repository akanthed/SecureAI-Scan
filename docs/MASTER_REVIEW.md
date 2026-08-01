# Master Review — SecureAI-Scan Growth Sprint

**Date:** 2026-08-01 · **Version:** 0.6.1 → work in this sprint applied on top

This is the final rollup: scores, what changed in this sprint, and the ranked backlog for what's next. See [`PROJECT_AUDIT.md`](PROJECT_AUDIT.md) for the detailed findings behind these scores.

## Scores (/100)

| Dimension | Score | Rationale |
|---|--:|---|
| **Detection quality** | 82 | Genuinely disciplined evidence-tier system, import-resolved sinks, and a real regression benchmark against public repos — better methodology than most commercial scanners in this space. Held back by 6 rules with no fixture-corpus recall proof (now documented in the audit appendix) and the Python surface being regex-based by design, not AST. |
| **Architecture** | 78 | Clean separation of scanning surfaces, a well-justified reason each is architecturally distinct (see `docs/Architecture.md`), and a genuinely good "why" for every non-obvious design choice (evasion-resistance inverting the usual heuristic-lowers-evidence rule). Docked for zero caching/incremental-scan support and each surface doing its own file discovery independently. |
| **Documentation** | 70 → improved this sprint | Was: excellent `CLAUDE.md` for an AI agent, near-nothing in `docs/` for a human contributor, thin `CONTRIBUTING.md`/`SECURITY.md`. This sprint added the missing `docs/` tree (Architecture, DetectionEngine, WritingRules, RuleDevelopment, ThreatModel, Performance, FAQ, Contributing) and wired it into the README. Still: root `CONTRIBUTING.md`/`SECURITY.md` remain thin stubs relative to the project's own subject matter. |
| **Maintainability** | 75 | `tsc --strict` clean, zero TODO/FIXME/HACK in `src/`, 2 runtime dependencies total, consistent rule shape. Docked because — until this sprint — the deobfuscation test suite silently didn't run under `npm test`, which is exactly the kind of gap that erodes maintainability invisibly. Fixed this sprint (see below), and it immediately surfaced a real bug, which is the strongest possible argument that this was worth fixing. |
| **DevEx** | 68 → improved this sprint | Command surface, flag validation messages, and `--help` quick-start examples are all above average. The silent-0-findings-on-a-bad-path bug (now fixed) was a real, dangerous gap for a security tool specifically. No progress indicator on long scans remains open. |
| **OSS readiness** | 60 → improved this sprint | No CI test gate, no PR template, no CODEOWNERS, no dependabot config, no Windows/macOS CI coverage — all real gaps for attracting outside contributors, all addressed in this sprint except enabling GitHub Discussions and creating a labels taxonomy, which require live repo-settings changes rather than committed files (flagged, not done, pending confirmation — see "Not done" below). |
| **Enterprise readiness** | 65 | SARIF output, baseline diffing, policy files, and an evidence-tier system that avoids alert fatigue are all enterprise-relevant strengths. Missing: no automated npm publish pipeline (currently a manual, single-point-of-failure process), no coverage measurement, no SLA-shaped security disclosure process beyond an email address. |
| **Performance** | 72 | No algorithmic problems found; the gap is entirely an absence of caching/incrementality, which is a real cost at scale but not urgent at current adoption size — correctly deferred, not ignored (see `docs/Performance.md`). |

**Overall: 73/100.** The core product — the detection engine and its precision discipline — is genuinely strong, arguably the standout part of the project. The score is held down almost entirely by project-scaffolding gaps (CI, docs, GitHub hygiene) that are cheap to fix and mostly were fixed this sprint, not by anything wrong with the detection approach itself.

## What this sprint actually changed

1. **Fixed a real, previously undetected bug** in `src/scanner/skill-bundle.ts`: the `GIT_TRANSIENT_FILE` regex's `^\.` catch-all (meant to skip hidden/transient files written inside `.git/`) also matched the literal directory name `.git` itself, causing the bundle walker to skip into `.git/` never — meaning SKL004's staged-payload detection inside `.git/` (the exact hiding place documented in arXiv:2607.02357) silently never fired. Found immediately upon wiring `deobfuscate.test.js` into `npm test` for the first time. Verified fixed and re-confirmed clean against the labeled Cisco skill-scanner corpus (6/6 malicious, 0 false positives) and all real bundles in `anthropics/skills`.
2. **Wired `deobfuscate.test.js` into `npm test`** (`test/run-tests.js`) — previously only ran via a direct, non-obvious invocation. This is the test suite covering the entire evasion-resistance module.
3. **Added `.github/workflows/ci.yml`** — build + `tsc --noEmit` + `npm test` on every PR and push to `main`, across a 3-OS × 2-Node-version matrix (Ubuntu/Windows/macOS × Node 20/22). Previously the only workflow was a non-blocking self-scan that never ran the test suite at all.
4. **Fixed the silent-0-files-on-bad-path CLI bug**: `secureai-scan scan <nonexistent-path>` now exits 1 with a clear error instead of exiting 0 with "no findings" — the most dangerous class of bug this audit found, since it fails in the direction (false confidence) the tool exists to prevent. Covered by a new case in `test/cli.test.js`.
5. **Added `.github/PULL_REQUEST_TEMPLATE.md`, `CODEOWNERS`, `dependabot.yml`.**
6. **Wrote the `docs/` tree**: `Architecture.md`, `DetectionEngine.md`, `WritingRules.md`, `RuleDevelopment.md`, `ThreatModel.md`, `Performance.md`, `FAQ.md`, `Contributing.md` — and linked all of it from the README.
7. **README additions**: a comparison table against Semgrep/Trivy/GHAS, a "See it work" section wiring in the existing (previously unreferenced) demo GIF and attack-flow diagrams, an ASCII architecture diagram, and Roadmap/Contributing sections — added to, not replacing, the existing README, which was already strong (evidence tiers, precision contract, real before/after regression numbers) and didn't need a rewrite.
8. **Wrote `docs/PROJECT_AUDIT.md`** (Phase 1) with severity-ranked findings and a rule-by-rule detection review appendix (Phase 4).

Every change above was verified: `npm run build && npm test` is green (101/101 tests), and the skill-bundle fix was independently re-validated against real-world corpora via `npm run regression`.

## Not done this sprint (explicitly, so it's not mistaken for "missed")

- **GitHub repo settings** (branch protection requiring the new CI workflow, enabling Discussions, creating a labels taxonomy) — these are live account/repo-settings changes, not committed files. Not made autonomously; flagged for the maintainer to apply directly, since they affect repository configuration visible to and enforced against every future contributor.
- **Automated npm publish workflow** — `PUBLISHING.md` documents one that was never committed. Deferred: publishing automation touches release credentials/secrets configuration, which is a higher-trust change than the rest of this sprint and deserves an explicit go-ahead.
- **Backfilling fixture-corpus coverage for the 6 under-verified rules** (AI011, MCP001, MCP003, VEC002, VEC003, VEC004) — real work, correctly scoped as its own follow-up per rule (see `docs/PROJECT_AUDIT.md` §1.3 and the appendix), not attempted wholesale in this pass to avoid rushing fixture quality on the exact thing this audit is arguing needs rigor.
- **Python AST rewrite, caching/incremental scanning** — both correctly identified as multi-week efforts in the audit; not attempted.
- **Committing/compressing `demo.gif` and the two attack diagrams properly** — the README now references them, but the 2.8 MB of PNGs already in git history and the 24.2 MB untracked GIF (flagged in the audit, §2.4) still need a real decision: compress-and-commit, host externally, or Git LFS. Left to the maintainer since it involves either rewriting recent history or setting up external hosting.

## Top 20 improvements ranked by impact (done vs. remaining)

| # | Improvement | Status |
|--:|---|---|
| 1 | CI runs build + tests on every PR | ✅ done this sprint |
| 2 | Wire `deobfuscate.test.js` into `npm test` | ✅ done — surfaced and fixed a real bug |
| 3 | Fix the `.git/` traversal bug in `skill-bundle.ts` | ✅ done this sprint |
| 4 | Fix silent-0-findings on a bad/nonexistent scan path | ✅ done this sprint |
| 5 | PR template, CODEOWNERS, dependabot.yml | ✅ done this sprint |
| 6 | `docs/` tree (Architecture, DetectionEngine, WritingRules, etc.) | ✅ done this sprint |
| 7 | README: comparison table, visuals section, architecture diagram | ✅ done this sprint |
| 8 | Backfill fixture coverage for AI011/MCP001/MCP003/VEC002-004 | ⏳ scoped, not started |
| 9 | Enable branch protection requiring the new CI workflow | ⏳ requires repo-settings access |
| 10 | Automated npm publish workflow on tag | ⏳ requires publish credentials decision |
| 11 | Resolve the 2.8 MB of committed PNGs / 24 MB untracked GIF | ⏳ requires a hosting decision |
| 12 | Progress indicator on long scans | ⏳ open, low effort |
| 13 | GitHub Discussions + labels taxonomy | ⏳ requires repo-settings access |
| 14 | Coverage measurement (`c8`/`nyc`) | ⏳ open |
| 15 | Strengthen `CONTRIBUTING.md`/`SECURITY.md` at repo root | ⏳ open |
| 16 | Model-configuration-risk rule (new detection capability) | ⏳ roadmap item, needs design pass |
| 17 | Agent-loop / iteration-cap rule (new detection capability) | ⏳ roadmap item |
| 18 | MCP privilege-escalation/scope-creep rule (MCP02 coverage gap) | ⏳ roadmap item |
| 19 | Shared file-discovery pass across the 4 scanning surfaces | ⏳ open, moderate effort |
| 20 | Python AST rewrite (replace regex scanner) | ⏳ large, tracked in ROADMAP.md, spike exists |

## Is this project ready for 100 / 1,000 / 10,000 stars?

**100 stars — yes, and probably already achievable.** The core pitch (evidence-tiered findings, dataflow proof, MCP/Agent Skill coverage nothing else has) is genuinely differentiated and the README now states that clearly with a comparison table. This tier is about discoverability and a credible first impression, both of which are in reasonable shape after this sprint.

**1,000 stars — plausible, with the caveat that CI/OSS hygiene needed to exist before outside contributors would trust the project enough to send PRs, which was the biggest blocker before this sprint and is now mostly closed.** What's left at this tier: the maintainer needs to actually turn on branch protection (item #9) so the new CI gate means something, and the demo GIF/diagrams issue (#11) should be resolved before a wider audience starts cloning the repo. A blog post or write-up of the `Cloak and Detonate` evasion-resistance work would likely be the single highest-leverage marketing move available, since it's a genuinely novel, verifiable claim (validated against a labeled corpus) rather than a generic feature announcement.

**10,000 stars — not yet, and the honest gap is scope, not quality.** A project at this scale in the security-tooling space (Semgrep, Trivy) either has a much broader detection surface or a very sharp, singular hook that gets shared organically. SecureAI-Scan's hook (MCP/Agent Skill poisoning, evasion-resistant, benchmarked against real attack corpora) is sharp and defensible, but MCP/Agent Skills are still an emerging surface — the ceiling here is coupled to how big that ecosystem gets, not to anything fixable by more engineering work on this repo alone. The Python AST rewrite (#20) would meaningfully widen the addressable audience once the current TS/JS-first design has more headroom to invest in it.
