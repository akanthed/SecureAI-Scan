# Detection Engine

This document explains the evidence-tier system — the core mechanism that lets SecureAI-Scan show zero false positives by default without also being blind. If you're adding or editing a rule, read this before [WritingRules.md](WritingRules.md).

## The problem this solves

Most static analyzers face a forced choice: flag aggressively and drown users in false positives, or flag conservatively and miss real issues silently. Neither is acceptable for a security tool — a scanner that cries wolf gets ignored (and then misses the finding that mattered), and a scanner that's quiet by default but also blind gives false confidence, which for a security tool is worse than no scanner.

The evidence-tier system is the resolution: **separate "how confident is this finding" from "should it be shown by default,"** and make the confidence claim itself falsifiable — a `proven` finding must be provably correct given what the code does, not just probably correct given what the code looks like.

## The three tiers

Defined in `src/scanner/types.ts` (`Evidence` type) and scored in `src/scanner/confidence.ts` (`evidenceConfidence()`):

- **`proven`** — an import-resolved sink with traced dataflow from a known-tainted source, or a parsed config fact (e.g. an MCP config with `"url": "http://..."` — plaintext HTTP is provably plaintext HTTP, no inference needed).
- **`likely`** — a resolved sink (the call is provably an LLM SDK call) with one heuristic hop — e.g. the argument *looks* like it contains user input based on naming/shape, but the dataflow wasn't fully traced back to an HTTP handler.
- **`heuristic`** — a pattern or proximity match with no resolved sink and no traced flow. Hidden by default; shown only with `--paranoid`.

**A default scan shows `proven` + `likely` only.** This is the whole precision claim in one sentence: nothing reaches the terminal by default unless the scanner can point at *why* it's confident, not just *that* it matched something.

## The rule that makes this work: sinks are resolved through imports

`resolveLlmSink()` in `src/scanner/rules/llm-rule-utils.ts` is the single most load-bearing function in the codebase. A function call is only classified as "an LLM call" if the identifier resolves — through actual import bindings, not name-matching — to a known SDK export (`openai`, `@anthropic-ai/sdk`, `ai`, `@google/genai`, LangChain, Bedrock, and others).

This is why `resolveLlmSink` treating *every* call into an LLM SDK module as a model invocation (regardless of method name) was a real bug, not a hypothetical: it caused `isToolUIPart` — a type guard the `ai` package exports right next to `generateText` — to be flagged as an LLM call in `vercel/ai`, cascading into 3 finding groups. The fix wasn't "loosen the check," it was "make the resolution more specific" (verb-aware, not just module-aware). See `CHANGELOG.md` for the full writeup.

The same discipline applies to sink detection more broadly: `AI005`'s `DANGEROUS_CALLEES` includes `"query"` for SQL-injection-style sinks, but `"query"` is also the Claude Agent SDK's own model-invocation method name (`claudeSdk.query({ prompt, options })`) — a shared method name across two completely different APIs caused a real false positive until the check was made import-aware rather than name-only.

## `getPromptParts`: always reuse, never reimplement

`llm-rule-utils.ts` exports `getPromptParts()`, which extracts prompt message parts *with role* (system/user/assistant) from a resolved LLM call. Every rule that needs to know "is this text going into a system prompt or a user message" should call this — not write an ad hoc extractor.

This isn't a style preference; a rule-specific reimplementation is exactly what caused the AI007 false-positive class: `chunks`, an extremely common variable name in LLM streaming-response code, was treated as unambiguous RAG evidence by a rule that didn't share the canonical prompt-part extraction logic and so lost the role context that would have disqualified it.

## Text-content rules need a shape, not a keyword

For rules like AI008 (system-prompt secret leakage), MCP008 (tool-poisoning injection phrases), and SKL002 (skill poisoning), there's no AST sink to resolve — the "evidence" is the shape of a string. The bar here: **a bare keyword/substring match is never enough to justify `proven` or even `likely`.**

Concretely, this ruled out a raw substring search for "secret" or "token" (AI008 originally did this — flagged narrative/fiction prompt text containing the bare English words "secret" or "token" with no requirement that the match look like an actual credential value) and a Python MCP001 check that flagged *any* `description=` field containing phrases like "system prompt" at `proven` tier regardless of whether the file had anything to do with MCP at all. Both were found via the real-world regression benchmark (`npm run regression` — see the README's "Testing & benchmarking" section), not the fixture corpus — the fixture corpus only proves the scanner behaves on code written to test it.

The fix pattern for this class of bug is always the same: require either a traced dataflow, an import-resolved sink, or a value/phrase shape specific enough that ordinary prose or unrelated identifiers can't collide with it (a real path like `~/.aws/credentials`, not the word "token"; bulk enumeration like `os.environ.items()`, not a single named env var lookup).

## Evasion resistance inverts the tier logic — on purpose

`src/scanner/deobfuscate.ts` and `src/scanner/skill-bundle.ts` are the one place in the codebase where a heuristic transform *raises* evidence instead of lowering it. Content checks there match against normalized variants (invisible-character-stripped, homoglyph-folded, string-splice-joined, intra-word-break-joined), and **a hit found only after deobfuscation is promoted to `proven`, not demoted** — ordinary prose does not contain a zero-width joiner inside "ignore previous instructions." The concealment itself is the evidence. See the README's "Evasion resistance" section for the full threat model this responds to (arXiv:2607.02357, the Gecko Security test-file vector).

This is a deliberate, narrow exception. It does not generalize — do not use it as precedent for loosening evidence requirements elsewhere.

## `isTestFilePath` and evidence demotion

`src/scanner/confidence.ts` also provides `demoteEvidence()` (downgrade one tier) and `isTestFilePath()` (matches test/example/demo/fixture path *segments*, not raw substrings — `examples/`, top-level `tests/`, and hyphenated directories like `ecosystem-tests/` all count). New rules touching request/user-controlled data should call `isTestFilePath` and demote evidence in matched paths — a rule that skips this is a latent false-positive source in any repo that ships example code, which is most repos. `isTestFilePath` itself was rewritten to be segment-based after its original narrow literal-match version (`/test/`, `/tests/` only) missed real-world directory naming conventions during the regression benchmark.

**The one deliberate exception:** SKL005 does *not* call `isTestFilePath`. A payload staged in `*.test.ts` is the published attack (test runners auto-execute those files on `npm test`) — demoting evidence there would defeat the rule's entire purpose. Do not "fix" that by adding the demotion back.

## Summary: the default failure mode to watch for

Every real false-positive class found in this codebase so far reduces to the same shape: **a keyword or substring match applied without enough surrounding context, given undeservedly high evidence.** When reviewing a new rule or a PR that touches an existing one, that's the question to ask first: does this finding's evidence tier reflect something actually proven about the code, or does it just reflect "the text looked like X"?
