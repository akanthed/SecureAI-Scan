# What we found scanning real repos

Most scanners prove their claims on fixtures they wrote themselves. We do that too ([`test-fixtures/`](../test-fixtures)), but a corpus you author yourself can't tell you how the scanner behaves on code you didn't write — so `npm run regression` runs the built CLI against a curated set of real, public LLM/MCP/RAG codebases and checks the result against a hand-reviewed baseline. This is what that actually turned up.

## The headline result: a labeled ground-truth test

[cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) ships an `evals/` corpus built to evaluate Agent Skill scanners — and unlike most real-world repos, its fixtures are pre-labeled: each one sits under a directory named `malicious/` or `safe/`. That turns a regression scan into a graded test instead of a judgment call.

Scanning it:

- **6/6 in-scope malicious fixtures fired** — invisible Unicode smuggled into a skill body (`SKL001`), a skill that downloads and `exec()`s a remote payload (`SKL005`), a skill whose body reads "Ignore all previous instructions..." (`SKL002`)
- **0 findings on anything labeled `safe/`**
- **0 findings** across all 18 real skill bundles in [anthropics/skills](https://github.com/anthropics/skills) and all 14 in [vercel/ai](https://github.com/vercel/ai) — no false alarms on skills nobody built to be malicious

The remaining Cisco eval categories (SQL injection, path traversal, resource exhaustion, generic `eval()` of a bare argument, a payload deliberately split across four files) are either outside the documented LLM/MCP/RAG scope or beyond same-file conjunction analysis — full reasoning per category is in the [CHANGELOG](../CHANGELOG.md). We'd rather say "out of scope" than stretch a rule until it starts guessing.

## The finding we're *not* going to oversell

Scanning [run-llama/llama_index](https://github.com/run-llama/llama_index) (3,839 files) surfaces 46 `VEC001` findings — "vector search called with no per-user/tenant access-control filter." Every one traces to the same shape, e.g. `llama-index-core/llama_index/core/indices/base.py:505`:

```python
def as_query_engine(self, llm=None, **kwargs):
    retriever = self.as_retriever(**kwargs)
    ...
```

This is not "llama_index is vulnerable." It's a generic base-class method — filters are meant to arrive through `**kwargs` from whatever an application passes in, and llama_index makes no claim that `as_retriever()` alone enforces tenant isolation. Calling this a bug in llama_index would be a mischaracterization of a library that's doing exactly what it's documented to do.

What it *is*: an accurate flag on a real, well-documented failure mode in production RAG systems — an application team wires up `index.as_retriever()`, ships it, and never adds the `filter=`/`namespace=` argument that scopes results to the current user or tenant. The retrieval call works fine in every test, because test data has no other tenant to leak. The gap only shows up when tenant B's documents come back in tenant A's answer. That's a real, recurring class of incident, and it's exactly the shape VEC001 is built to catch **in application code that calls into a library like this** — the library scan is a demonstration of the pattern, not an accusation against the library.

## Precision isn't free — here's what it cost to earn

The same regression scan is also how we caught our own bugs. An earlier run against `vercel/ai` (5,691 files) came back with 40 findings. Every one was hand-reviewed against source and confirmed a false positive, tracing to three root causes:

1. `resolveLlmSink` treated *any* call resolving to an LLM SDK module as a model invocation — flagging `isToolUIPart`, a type guard the `ai` package exports next to `generateText`, as an LLM call.
2. `AI005`'s dangerous-sink list included `"query"` for SQL-injection-style sinks — which is also a legitimate agent invocation verb, so the Claude Agent SDK's own `claudeSdk.query({ prompt, options })` got flagged as "LLM output passed to a dangerous sink."
3. A shared request-source matcher fired on any parameter merely named `params` — not necessarily HTTP request data — so a URL-scheme validator (`assertOpenLinkParams(params: unknown)`) was flagged as "MCP server URL from user input."

All three were fixed at the root cause, not patched at the call site, and pinned as permanent fixtures so they can't regress silently. Full numbers, plus the same before/after treatment for `vercel/ai`, `openai-node`, `anthropic-sdk-typescript`, and `modelcontextprotocol/typescript-sdk`, are in the [Testing & benchmarking](../README.md#testing--benchmarking) section of the README.

## Run it yourself

```bash
npm run regression                # scan the full curated repo set
npm run regression -- llama_index # scan just one repo by name
```

The baseline that gates this (`test/regression-baseline.json`) is a record of findings someone actually read against their source line — not a mute button. Every fingerprint not already in it fails the build.
