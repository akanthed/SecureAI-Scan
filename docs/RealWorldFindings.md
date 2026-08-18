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

## A live example: adding LiteLLM to the regression set found three bugs before it found one real issue

When we added static `config.yaml` scanning for LiteLLM Proxy (`LLC001`–`LLC003`: hardcoded secrets, plaintext provider endpoints, missing guardrails), none of the repos already in the regression set exercise those rules — none of them ship a LiteLLM proxy config. So we added [BerriAI/litellm](https://github.com/BerriAI/litellm) itself, the official repo, specifically to get real coverage. It's a large, real production monorepo (6,978 TS/JS files, thousands more in Python) — a genuinely harder target than our own fixtures.

First pass surfaced two new false-positive classes and one unrelated but serious robustness bug, in that order:

1. **Line misattribution.** `LLC001` correctly detected that *some* entry in a `model_list` had a hardcoded secret, but anchored the finding to the first line in the file containing the string `api_key` — not the line that actually held the offending value. In a config with dozens of `api_key:` entries, that meant a reported finding could point straight at an `os.environ/...` reference and contradict its own evidence. Fixed by anchoring on the flagged *value* instead of the key name (unique per credential, unlike the key).
2. **Placeholder-value false positives.** LiteLLM's own docs and tests inline dummy values like `fake-key`, `my-fake-key`, `sk-lar1-demo` to demonstrate config shape — not real secrets. `LLC001` initially flagged all of them. Fixed with a placeholder-word check plus a "does this look like a random credential blob or a human-typed phrase" heuristic (longest unbroken alphanumeric run < 12 chars ⇒ not credential-shaped) rather than guessing at a denylist of exact strings.
3. **A rule crash was silently killing the entire scan.** Unrelated to LiteLLM's config files — a ts-morph type-checker failure on one file in the repo's Next.js admin dashboard (a large monorepo with multiple independent `tsconfig.json` files merged into one project) took down the *whole* scan, discarding every rule's findings, not just the one that crashed. This is worse than any false positive: a scan that silently reports nothing instead of erroring looks identical to "clean." Fixed by isolating each rule's `run()` — one rule failing now logs a warning and the rest of the scan continues.

Two more, smaller false positives surfaced once the scan could actually complete against the full repo:

4. `MCP001` (Python) matched the phrase "system prompt" inside an *admin-UI settings description* — plain English describing an unrelated caching feature, in a module-level dict inside a 17,000-line file. The scoping guard meant to require real MCP-listing context fell back to the entire file when a match wasn't inside a function, so "the file mentions MCP somewhere" (true of nearly any file that size in this codebase) satisfied it. Capped the fallback to a small line window instead of the whole module.
5. `MCP002` (TypeScript) flagged a pure URL-parsing utility (`extractMCPToken(url: string)`) as "MCP server URL from user input" for no reason other than "url" being the name of one of its own parameters — a blanket rule that treated *every* function parameter as request-tainted regardless of whether the function had anything to do with handling a request. The known-vulnerable fixture never needed this: it matches `req.body.serverUrl` directly. Removed the blanket taint.
6. `VEC001` matched Python's stdlib `re.search(r"/vector_stores/([^/]+)/", path)` — ordinary URL-path parsing — as a vector-store similarity search, purely because the regex *pattern string* contained the substring "vector" and the call syntactically looked like `.search(...vector...)`. Added an exclusion for `re.search`/`regex.search`.

After all six fixes: **zero LLC001/LLC002 false positives, one confirmed-real `LLC002` finding** (a proxy config routing to an internal `vllm-command` host over plain `http://`, in `litellm/proxy/_super_secret_config.yaml`), and the rest of the rule set continuing to run clean against the same repo. Every fix shipped with a permanent fixture under `test-fixtures/safe/`, named for the pattern, so none of these six can regress silently.

This is what "zero tolerance for false positives" costs in practice: not zero bugs, but a standing habit of reading every new finding against its source line before trusting it, on code we didn't write.

## Run it yourself

```bash
npm run regression                # scan the full curated repo set
npm run regression -- llama_index # scan just one repo by name
```

The baseline that gates this (`test/regression-baseline.json`) is a record of findings someone actually read against their source line — not a mute button. Every fingerprint not already in it fails the build.
