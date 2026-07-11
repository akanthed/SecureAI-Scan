// Vulnerable: raw prompt content and an API key are logged in an LLM file.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handler(req: { body: { question: string } }) {
  requireAuth(req);
  const prompt = `Answer briefly: ${sanitizeInput(req.body.question)}`;
  console.log("sending prompt", prompt);
  console.log("using apiKey", process.env.OPENAI_API_KEY);

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: prompt }],
  });
}

function sanitizeInput(input: string): string {
  return input.slice(0, 500);
}

function requireAuth(req: unknown): void {
  if (!req) throw new Error("Unauthorized");
}
