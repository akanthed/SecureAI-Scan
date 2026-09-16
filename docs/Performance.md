# Performance

Measured, not estimated. Numbers below come from `node --cpu-prof` runs against the regression corpus (`npm run regression`), largest repo `vercel/ai` at 5,691 files.

## Where the time actually goes

The dominant cost in a scan is AST traversal — not type resolution, not I/O, not rule logic. A CPU profile attributed **~95s of a 150s** `vercel/ai` scan to ts-morph descendant iteration alone (`getCompilerDescendantsIterator`, `getCompilerForEachDescendantsIterator`, `getCompilerChildren` and their node-wrapper cache): more than everything else in the profile combined.

The cause was structural. Each of ~20 rules ran its own `sourceFile.getDescendantsOfKind(CallExpression)` or `sourceFile.getDescendants()` per file, so every file's AST was walked ~20 times per scan — and nested functions were re-walked once per enclosing scope on top of that.

Two fixes, both in [`src/utils/ast.ts`](../src/utils/ast.ts):

- **One walk per file, shared.** `getFileCalls` / `getFileFunctions` build a per-file index in a single `forEachDescendant` pass, memoized in a `WeakMap`. Rules consume the index instead of walking.
- **Containment by binary search.** `getCallsWithin(fn)` slices that index rather than walking the subtree — the index is in pre-order, so a node's descendants are a contiguous run of it. Spans come from `compilerNode.pos`/`.end`, captured during the indexing walk; an earlier version used `getStart()`, which rescans leading trivia on every probe and was *slower* than the walk it replaced.

A third fix, in [`src/scanner/rules/llm-rule-utils.ts`](../src/scanner/rules/llm-rule-utils.ts): `resolveLlmSink` now checks the generation-shaped method name and the file's imports *before* asking the type checker anything. `resolveIdentifierModule` can only ever report a specifier the file itself imports, so a file with no LLM SDK import cannot produce a resolved sink — the type checker never needed consulting for the overwhelming majority of files.

### Result

| | before | after |
|---|---:|---:|
| `vercel/ai` (5,691 files) | 217s | **62s** |
| `npm test` (full suite) | 42s | **16s** |

Findings are identical before and after across the full regression corpus. This was a cost change, not a behaviour change — and it is verified as such, not assumed.

## Guarding the optimization

`getCallsWithin`'s contiguity assumption is the kind that fails silently: if it broke, rules would stop seeing calls and the scanner would simply go quiet, which is the worst failure mode a scanner has. [`test/ast-index.test.js`](../test/ast-index.test.js) therefore asserts the index and the slice against ts-morph's *own* `getDescendantsOfKind` walk — exact membership and document order — over a fixture with nested arrows, class methods, and tagged templates.

There is no wall-clock perf gate: timing tests are flaky on shared CI runners, and the correctness test above is what actually protects the behaviour.

## What's still not done

- **No incremental scanning.** Every run parses every file from scratch, including in CI on every PR. `--baseline` filters *findings* after the fact; it does not skip unchanged files. Real incremental support needs file hashing plus care that cross-file dataflow rules re-evaluate when any file in the flow changes.
- **No worker-thread parallelism.** Rules run against a shared in-memory ts-morph `Project`, which is not trivially shareable across threads.
- **No shared file-discovery pass.** The four scanning surfaces (TS/JS, Python, MCP config, Agent Skill bundles — see [Architecture.md](Architecture.md)) each glob the repo independently. Lowest-effort remaining win.

## What contributors should do

If you touch `scan.ts`, `project.ts`, `llm-rule-utils.ts`, or add per-file work to a rule: time `npm run regression` on `vercel/ai` and `llama_index` before and after, and say so in the PR. **Never reintroduce a whole-file `getDescendants*` call in a rule** — use the shared index. That single pattern cost 3.5× scan time.

## Progress feedback

A scan prints a single `Scanning <path>...` line to stderr before starting (gated on `isTTY`, so CI and piped logs stay clean). There's no spinner: the pipeline is synchronous CPU-bound work with no natural yield point. When triaging a "scanner seems frozen" report, check `--debug` first to confirm it's progressing.
