// Safe: user input is separated and encoded, not injected into system prompt.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

function sanitize(input: string): string {
  return input.replace(/[\r\n]/g, " ").slice(0, 2000);
}

export async function handler(req: { body: { input: string } }) {
  requireAuth(req);
  const userInput = sanitize(req.body.input);

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "system", content: "You are a secure assistant." },
      { role: "user", content: userInput },
    ],
  });
}

function requireAuth(req: { user?: { id: string } }) {
  if (!req.user) {
    throw new Error("Unauthorized");
  }
}
