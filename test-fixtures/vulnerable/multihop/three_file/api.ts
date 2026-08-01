// Vulnerable: request data crosses TWO function-call boundaries
// (api.ts -> lib/middle.ts -> lib/llmclient.ts) before reaching an LLM
// system prompt. Proves the interprocedural walker's hop cap of 2 still
// finds a real 3-file chain.
import { middleware } from "./lib/middle";

export async function handler(req: { body: { input: string } }) {
  await middleware(req.body.input);
}
