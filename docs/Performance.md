# Performance

Current state, honestly, as of v0.6.1 — this is a snapshot for contributors thinking about scanning large repos, not a set of benchmarks to hit.

## How a scan actually runs

- `src/scanner/project.ts` builds one `ts-morph` `Project` from the target path per invocation. There is no caching or incremental-scan support: every run parses every file from scratch, including in CI where the same repo is scanned on every PR.
- `src/scanner/scan.ts` runs fully synchronously and serially. Each rule in `RULES` walks the *entire* set of source files independently (`RULES.map(rule => rule.run(context))`) — rules do not share a single traversal, so the cost is roughly O(rules × files × AST nodes), not O(files × AST nodes).
- The four scanning surfaces (TS/JS, Python, MCP config, Agent Skill bundles — see [Architecture.md](Architecture.md)) each do their own file discovery / glob pass independently, rather than sharing one file list from a single walk of the repo.
- `--baseline` diffs *findings* against a saved baseline, not files — it doesn't skip re-scanning unchanged files, it only filters which findings get reported afterward.
- The only asynchronous I/O in the default scan path is `--check-dependencies`'s registry lookups (network calls to npm/PyPI); everything else is synchronous.

None of this is an algorithmic problem (no O(n²) pattern was found scanning the codebase) — it's an absence of caching and sharing, which mainly matters as repo size grows. On the repos in the regression benchmark (`npm run regression` — up to `vercel/ai`'s 5,511 files), scan time in the multi-second range, reported in the terminal header (`v0.6.1 · N files · X.Xs`).

## What's not done yet, and why it's not urgent

- **No worker-thread parallelism.** Rules currently run against ts-morph's in-memory `Project`, which isn't trivially thread-safe to share across workers without real design work. Given current scan times are seconds, not minutes, this hasn't been a reported pain point.
- **No incremental scanning (only re-analyze changed files).** Would require tracking file hashes/mtimes and being careful that dataflow rules spanning multiple files still get correctly re-evaluated when an unrelated file in the flow changes. Worth doing once a large-monorepo user reports scan time as an actual blocker — not worth the complexity budget speculatively.
- **No shared file-discovery pass across the four surfaces.** Lower effort than the above two, and the most likely first fix if this area gets prioritized — see `docs/PROJECT_AUDIT.md` §3.4.

## What contributors should do today

If you're touching the scan pipeline (`scan.ts`, `project.ts`, or a rule that does heavy work per file), the practical check is: run `npm run regression` and compare wall-clock time before/after on the two largest repos in the set (`vercel/ai`, `llama_index`) — there's no formal perf test, so this is a manual sanity check, not a gate. Flag a regression in your PR description if you see one; don't silently absorb it.

## Progress feedback

There is currently no progress indicator during a scan — nothing prints between invocation and the final report. On a large repo this can look hung even though nothing is actually stuck. This is a UX gap tracked separately in `docs/PROJECT_AUDIT.md` §3.5, not a performance problem per se, but worth knowing if you're debugging a "the scanner seems frozen" report — check `--debug` output first to confirm it's making progress before assuming a real hang.
