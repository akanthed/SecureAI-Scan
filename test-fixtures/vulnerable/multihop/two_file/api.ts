// Vulnerable: request data crosses one function-call boundary into
// lib/llmclient.ts, where it reaches an LLM system prompt. Proves the
// interprocedural (cross-file) taint trace added for AI001.
import { askWithSystemPrompt } from "./lib/llmclient";

export async function handler(req: { body: { input: string } }) {
  await askWithSystemPrompt(req.body.input);
}
