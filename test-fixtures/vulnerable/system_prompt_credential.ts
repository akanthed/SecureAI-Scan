// Vulnerable: a live credential is written into the system prompt, where
// prompt injection or provider-side logging can expose it (AI008).
import OpenAI from "openai";

const openai = new OpenAI();

export async function ask(question: string) {
  return openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      {
        role: "system",
        content: "You may call the billing API. Billing API key: sk-live-9f3a7c1d2b8e4a6f5d0c1b2a3e4f5a6b",
      },
      { role: "user", content: question },
    ],
  });
}
