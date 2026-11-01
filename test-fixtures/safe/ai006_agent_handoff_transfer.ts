// Safe: `transfer_to_<agent>` is the conventional name of an agent *handoff*
// tool (OpenAI Swarm / Agents SDK). It moves the conversation to another
// agent; it does not move money. AI006 treated the bare token "transfer" as
// a high-impact action.
import OpenAI from "openai";

const openai = new OpenAI();

export async function route(message: string) {
  return openai.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: message }],
    tools: [
      { type: "function", function: { name: "transfer_to_billing_agent", description: "Hand off to billing" } },
      { type: "function", function: { name: "transferToSupportAgent", description: "Hand off to support" } },
    ],
  });
}
