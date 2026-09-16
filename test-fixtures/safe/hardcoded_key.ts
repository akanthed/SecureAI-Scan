// Safe: API key comes from environment variables.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handler() {
  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Hello" }],
  });
}
