// Safe: an LLM/agent SDK's own .query() invocation is not a "dangerous sink"
// receiving LLM output, even though the bare verb "query" also name-matches
// a SQL sink pattern (db.query(sql)) elsewhere in this same rule.
//
// (Regression fixture: AI005's DANGEROUS_CALLEES list includes "query" for
// SQL-injection-style sinks (pool.query(untrustedSql)). GENERATION_METHODS in
// llm-rule-utils.ts also includes "query" as a legitimate LLM/agent
// invocation verb. Found scanning vercel/ai's own Claude Code harness (same
// import/cast shape reproduced here): claudeSdk.query({ prompt, options }) —
// the model invocation itself — was flagged as "LLM output passed to a
// dangerous sink" purely because its method name is "query".)
import * as claudeAgentSdk from "@anthropic-ai/claude-agent-sdk";

const claudeSdk = claudeAgentSdk as any;

export async function runTurn(prompt: string, model: string | undefined) {
  const stream = claudeSdk.query({
    prompt,
    options: { ...(model ? { model } : {}), includePartialMessages: true },
  });
  for await (const event of stream) {
    console.log(event);
  }
}
