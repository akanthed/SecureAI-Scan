// Vulnerable: LLM response is parsed as JSON with no schema validation.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function extractOrder() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Extract the order as JSON." }],
  });

  const raw = completion.choices[0].message.content ?? "";
  const order = JSON.parse(raw);
  return order;
}
