// Vulnerable: user input is interpolated directly into a system prompt.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handler(req: { body: { input: string } }) {
  // User input flows into the system prompt via template literal.
  const systemPrompt = `You are a secure assistant. User says: ${req.body.input}`;

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: "Help me." },
    ],
  });
}
