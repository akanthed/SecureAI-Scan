// Vulnerable: LLM call happens before auth check.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handler(req: { user?: { id: string } }) {
  // LLM call happens before any auth check.
  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Summarize recent activity." }],
  });

  // Auth check happens after the LLM call.
  if (!req.user) {
    throw new Error("Unauthorized");
  }
}
