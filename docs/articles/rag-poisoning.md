---
title: "RAG poisoning: when retrieved content becomes a prompt"
published: false
tags: rag, security, ai, llm
canonical_url: https://github.com/akanthed/SecureAI-Scan
---

Prompt injection usually gets framed as a user-input problem: sanitize what the human types, and you're covered. RAG breaks that framing. The instructions your model follows don't have to come from the person talking to it — they can come from a document someone else uploaded weeks ago, sitting in a vector store, waiting for a similarity search to surface it into someone else's prompt.

## The attack, in one picture

![RAG poisoning attack flow: a document with hidden instructions is uploaded, embedded, and stored; a later query retrieves it and the LLM executes the injected instruction](../../rag-poisoning-diagram.png)

Three phases, and the exploit is already over by the time anyone notices:

1. **Malicious upload.** A document goes into the ingestion pipeline containing instructions invisible to a human skim — the same invisible-Unicode and phrasing tricks used in MCP tool poisoning, just delivered through a document instead of a tool description.
2. **Ingestion and storage.** The document is chunked, embedded, and stored in the vector database alongside every legitimate document. Nothing about ingestion distinguishes it — it *is* a legitimate document, structurally. The payload is content, not a malformed file.
3. **Retrieval and exploitation.** Some unrelated later query happens to be semantically close enough that the poisoned chunk gets retrieved and dropped into the prompt as "context." The model has no way to know this text arrived from an attacker rather than from a trusted knowledge base — it's just tokens in the context window now, and if the prompt template concatenates retrieved content into the system or developer role rather than a clearly user/data-scoped one, those tokens carry system-level trust.

The gap between upload and exploitation can be arbitrary — the payload sits dormant until a query happens to retrieve it. That's what makes this a poisoning story rather than an injection story: the attacker doesn't need to be in the conversation at all.

## What actually gets checked

Five rules, split across two different failure modes:

- **AI007 — retrieved content interpolated into a privileged prompt.** Traces whether retrieved RAG content lands in a system/developer-role message rather than a user/data-scoped one. This is the direct analog of MCP tool-poisoning's "description reaches the system prompt" pattern — same threat model, different delivery mechanism.
- **VEC001 — vector search with no tenant/user filter.** Not about poisoned content at all — about isolation. A shared vector index searched with no per-user or per-tenant scoping means tenant B's documents can surface in tenant A's answer, poisoned or not.
- **VEC002 — unbounded or user-controlled search limit.** A `limit`/`top_k` parameter the caller controls without a cap invites resource exhaustion or an attacker fishing for how much of the index they can pull back.
- **VEC003 — user content ingested into a shared store.** Content a user submits going straight into the same index everyone else's queries retrieve from, with nothing marking it as user-originated or lower-trust.
- **VEC004 — ingestion without tenant/namespace tagging.** The write-side counterpart to VEC001: if nothing tags a document's tenant at ingestion time, no filter downstream can ever scope it correctly, no matter how careful the retrieval code is.

## The false positive that shaped AI007

Early versions of this scanner treated `chunks` — one of the single most common variable names in any LLM streaming or RAG codebase — as unambiguous evidence of RAG content flowing into a prompt. Scanning `vercel/ai`'s own source, that alone accounted for a large share of a 773-finding false-positive run against a 5,691-file repo. `chunks` shows up constantly in code that has nothing to do with retrieval: streaming response handling, batch processing, anything iterating in pieces. A bare identifier match with no dataflow trace behind it isn't evidence — it's a coincidence waiting to happen at scale.

The fix was the same one behind most of this project's precision corrections: stop trusting a variable *name* and require the trace to actually resolve to a real retrieval call and a real prompt sink. `getPromptParts` (shared across every rule that touches prompt content) exists specifically so no individual rule re-implements this extraction ad hoc — that duplication is exactly what let the AI007 false-positive class in.

## The finding we chose not to oversell

Scanning `run-llama/llama_index` — a RAG framework, not an application — surfaces 46 `VEC001` hits, every one tracing to the same generic library method: `as_query_engine()` / `as_retriever()`, defined to accept a `filter=`/`namespace=` argument from *whatever the caller passes in*. That's not a bug in llama_index. It's a framework doing exactly what it's documented to do — leaving tenant scoping to the application built on top of it.

What it *is*, honestly: the exact real-world failure mode VEC001 exists to catch, just one layer removed. A team wires up `index.as_retriever()`, ships it, and every test passes — because test data has no second tenant to leak into the response. The gap shows up the first time it matters, in production, when tenant B's documents come back in tenant A's answer. Flagging the library call is a demonstration of the pattern, not an accusation against the library — and calling llama_index "vulnerable" over this would have been a real mischaracterization we chose not to make.

Auditing `awslabs/mcp`'s own Valkey vector-search MCP server turned up the application-side version of the same shape directly: a `filt` string the *caller* supplies reaches `ft.search()` with nothing enforcing that it's actually scoped to the authenticated user — a real, `likely`-tier finding, not a library-internals artifact.

## Try it

```bash
npx --yes secureai-scan scan .
secureai-scan explain VEC001    # exploit walkthrough + before/after fix, for any rule
```

Full rule catalog, evidence-tier methodology, and the real-repo regression numbers behind these claims: [github.com/akanthed/SecureAI-Scan](https://github.com/akanthed/SecureAI-Scan).
