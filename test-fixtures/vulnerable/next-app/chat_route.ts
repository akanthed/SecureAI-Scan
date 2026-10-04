// Vulnerable: Next.js App Router route (Fetch-API Request). The destructured
// result of `await req.json()` reaches the Vercel AI SDK `system` prompt.
// Previously invisible: AI001 only recognized Express-style `req.body.x`.
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

export async function POST(req: Request) {
  const { messages, persona } = await req.json();
  const result = streamText({
    model: openai("gpt-4o"),
    system: `You are a support agent. Persona: ${persona}`,
    messages,
  });
  return result.toDataStreamResponse();
}
