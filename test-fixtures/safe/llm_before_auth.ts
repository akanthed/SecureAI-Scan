// Safe: auth check happens before any LLM usage.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

function requireAuth(req: { user?: { id: string } }) {
  if (!req.user) {
    throw new Error("Unauthorized");
  }
}

export async function handler(req: { user?: { id: string } }) {
  requireAuth(req);

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Summarize recent activity." }],
  });
}
