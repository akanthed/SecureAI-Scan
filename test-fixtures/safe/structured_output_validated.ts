// Safe: LLM JSON response is validated with a Zod schema before use. Added
// after fixing AI012's hasSchemaValidationNearby — the previous plain
// ".parse(" substring match collided with JSON.parse itself, so this
// fixture locks in that a real schema-validator .parse() call (Zod's, here)
// still correctly suppresses the finding once JSON.parse is excluded from
// the "safe" match specifically.
import OpenAI from "openai";
import { z } from "zod";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

const OrderSchema = z.object({ id: z.string(), total: z.number() });

export async function extractOrder() {
  const completion = await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Extract the order as JSON." }],
  });

  const raw = completion.choices[0].message.content ?? "";
  const order = OrderSchema.parse(JSON.parse(raw));
  return order;
}
