// Vulnerable: entire user object is sent to the LLM as JSON.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handler(req: { user: { email: string; phone: string; id: string } }) {
  const user = req.user;

  // Sends full user object to LLM.
  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "user", content: JSON.stringify(user) },
    ],
  });
}
