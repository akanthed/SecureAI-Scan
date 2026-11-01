// Vulnerable: the model is handed a destructive tool and nothing in scope
// asks a human before it runs (AI006).
import OpenAI from "openai";

const openai = new OpenAI();

export async function cleanup(instruction: string) {
  return openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: instruction }],
    tools: [
      { type: "function", function: { name: "delete_customer_records", description: "Delete records" } },
      { type: "function", function: { name: "transfer_funds", description: "Move money between accounts" } },
    ],
  });
}
