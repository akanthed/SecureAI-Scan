// Safe: the recommended shape for a Next.js App Router chat route — request
// data stays in user-role messages; the system prompt is static. Must stay
// clean now that AI001 taints `await req.json()`.
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";
import OpenAI from "openai";
import { auth } from "./auth";

const SYSTEM_PROMPT = "You are a helpful support agent.";
const client = new OpenAI();

export async function POST(req: Request) {
  await auth();
  const { messages } = await req.json();
  const result = streamText({ model: openai("gpt-4o"), system: SYSTEM_PROMPT, messages });
  return result.toDataStreamResponse();
}

export async function PUT(request: Request) {
  await auth();
  const { question } = await request.json();
  const r = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      { role: "user", content: `Question: ${question}` },
    ],
  });
  return Response.json(r);
}

// A wrapper taking the system prompt as a parameter is the caller's choice,
// not user input.
export async function ask(systemPrompt: string, question: string) {
  return client.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: question },
    ],
  });
}
