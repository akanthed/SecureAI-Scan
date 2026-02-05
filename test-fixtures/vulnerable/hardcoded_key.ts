// Vulnerable: hardcoded API key in source code.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: "sk-test-hardcoded-1234567890" });

export async function handler() {
  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Hello" }],
  });
}
