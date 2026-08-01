# Rule Development Workflow

This is the day-to-day loop for working on detection logic — [WritingRules.md](WritingRules.md) is the step-by-step checklist for a *new* rule; this doc is about the iteration loop, debugging, and how changes get reviewed, whether you're adding a rule or fixing one.

## Local loop

```bash
npm run build              # tsc compile, src/ -> dist/
node dist/index.js scan test-fixtures/vulnerable/<your-fixture> --paranoid --debug
```

Use `--paranoid --debug` while iterating: `--paranoid` shows `heuristic`-tier findings too (useful to see what your rule *would* catch before you tighten evidence requirements), `--debug` prints every file scanned and which rules ran, which catches "my rule silently isn't running on this file" before it looks like a logic bug.

```bash
npm test                   # build + full test suite (node:test, no separate runner)
node --test test/corpus.test.js         # just the precision-gate corpus
node --test test/deobfuscate.test.js    # NOT wired into npm test yet — run explicitly
```

`test/corpus.test.js` is the fast feedback loop: every fixture in `test-fixtures/vulnerable/` must fire its expected rule at `proven`/`likely`, every fixture in `test-fixtures/safe/` must produce zero `proven`/`likely` findings. This is fast and deterministic, but it only proves the scanner behaves on code written specifically to test it — see the next section for why that's not sufficient on its own.

## The regression scan — the step most likely to be skipped, and the most important one

```bash
npm run regression                # full curated repo set
npm run regression -- --fresh     # re-clone everything first
npm run regression -- openai-node # one repo, faster loop
```

`scripts/regression-scan.js` clones a curated set of real public repos (OpenAI/Anthropic/Vercel AI SDKs, official MCP servers and SDK, LlamaIndex, `anthropics/skills`, `cisco-ai-defense/skill-scanner`) into `.regression-cache/` (gitignored, cached — `--fresh` forces a re-clone) and scans each with the built CLI.

**There is no pass/fail threshold.** Upstream repos change, so a fixed expected count would be brittle. Instead: read every `proven`/`likely` finding it prints against its actual source line.

- Real issue in that repo → expected, leave it.
- Not a real issue → a bug in your rule. Fix the root cause (not the specific call site), then add the offending pattern as a new fixture under `test-fixtures/safe/` with a comment noting which repo/file it came from, so `npm test` locks the fix in permanently and it can't regress silently later.

Every documented false-positive class in `CLAUDE.md`/`CHANGELOG.md` was found this way, not by the fixture corpus — the corpus can't catch a bug in a rule if nobody wrote a fixture that happens to trigger it. Real repos have shapes nobody would think to write as a test fixture.

## Reviewing a rule PR (what a maintainer checks)

1. Does the rule resolve its sink through imports, or through a name match? (Reject name-matching alone.)
2. Does the evidence tier reflect something actually provable, or does it just feel about right?
3. Are there both `vulnerable/` and `safe/` fixtures, and is the `safe/` one a genuinely plausible near-miss, not a token gesture?
4. Was `npm run regression` actually run, and if it surfaced findings, were they triaged (not just eyeballed as "looks fine")?
5. Is there a catalog entry (`catalog.ts`) *and* an explainer entry (`explainer.ts`)? The second one fails silently if skipped.
6. Does the change stay in scope (LLM/MCP/RAG-shaped risk) — see the "Scope" note in `CLAUDE.md`. A generic SAST/secret-scanning rule, however well-intentioned, gets rejected even if it would catch a real incident, because a rule broad enough to catch generic business-logic payloads fires constantly on ordinary code. The correct fix for that class of gap is a `DEP003` advisory or an honest documented limitation, not a new heuristic pattern rule.

## Debugging a reported false positive

1. Reproduce: `node dist/index.js scan <path-to-the-file> --debug`.
2. Find which rule fired and read its `run()` function for the exact condition that matched.
3. Ask: is the evidence tier this finding got actually earned? If the condition is a bare keyword/substring match with no import resolution or dataflow trace, that's very likely the bug — see [DetectionEngine.md](DetectionEngine.md)'s "default failure mode" section.
4. Fix at the root cause (tighten the resolution logic or the shape requirement), not by special-casing the one file that revealed it.
5. Add the reported pattern as a new `test-fixtures/safe/` fixture so it can't regress.
