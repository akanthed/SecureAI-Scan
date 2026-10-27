# Published recall corpus with mutations: design

## Intent and why

secureai-scan's downloads are flat. The strongest trust signal so far is the CVE-pair check (vulnerable commit fires, fix commit clean) plus the scan of 25 clean MCP servers, documented in `docs/RealWorldFindings.md`. A dev.to commenter asked for two things: small harmless mutations around the real cases (extra wrapper, alias, shell option) to prove recall survives refactors without inflating false positives, and publication of the result as a regression corpus.

Goal: a reproducible, citable corpus and a one-command runner (`npm run corpus`) that prints recall and precision with evidence. Secondary goal: the mutations expose real recall gaps in MCP013/MCP014, which then get fixed.

## Goals

- Case manifest `corpus/cases.json`: repo, vulnerable SHA, fix SHA, expected rule, expected tool or file, for the six published CVE pairs.
- Per case, 3-5 mutation patches in `corpus/mutations/<case>/*.patch`, applied on top of the vulnerable checkout. Each must still fire the same rule at `proven` or `likely`.
- Mirror mutations on the fix checkout (a real guard written in a different style). Each must stay clean.
- Clean set manifest `corpus/clean.json`: the 25 servers with pinned SHAs. Expected: zero default-tier MCP013/MCP014.
- Runner `scripts/corpus-run.js` plus `npm run corpus`: clones at pinned SHAs into a gitignored cache (reuse the approach in `scripts/regression-scan.js`), runs the built CLI, prints a recall/precision table, exits non-zero on any miss. `--json` output so other scanners can be scored on the same cases.
- A `docs/Corpus.md` explaining the method and how to add a case.
- `test/cli.test.js`-style test for the runner, because it drives the built binary.

## Non-goals

- No vendoring of third-party source. Manifest plus patches only. Patches carry minimal context lines.
- No general-purpose SAST. Scope stays LLM/MCP/RAG.
- No new rules. Only fixes to MCP013/MCP014 that the mutations prove are needed.

## Anti-goals

- Making recall pass by loosening guards. A recall fix that adds any new `proven`/`likely` finding in `test-fixtures/safe/`, the clean set, or `npm run regression` fails.
- Baselining a finding that was not read against its source line.

## Constraints

- Follow CLAUDE.md: `npm run build` before tests, `npm test` green, `npm run regression` green after any rule change.
- Each rule fix is made at the root cause. Each fixed false positive gets a permanent fixture in `test-fixtures/safe/`.
- Publishing, commits, and the dev.to reply are the user's call. Nothing is committed or posted without being asked.

## Decided with the user

- Manifest plus patches, not vendored code.
- Built in this repo under `corpus/` first, split out later if it stabilises.

## My calls (flagged)

- Mutation categories: wrapper function, aliased import or renamed variable, added shell option or flag, sink moved to a helper in another file, template interpolation changed to concatenation.
- Case IDs follow the CVE number.
- Runner is plain Node like the other scripts in `scripts/`.

## Left to the builder

- Exact patch format (`git apply` against the checkout is expected).
- Table layout and JSON schema.
- Which of the 25 clean servers to include if SHAs cannot be resolved for some.
