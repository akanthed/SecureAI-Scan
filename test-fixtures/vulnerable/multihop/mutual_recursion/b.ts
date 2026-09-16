import { callA } from "./a";
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

// Calls back into a.ts before reaching the LLM sink — proves the walker's
// cycle guard produces exactly one finding rather than looping or
// duplicating when the call graph isn't a simple chain.
export function callB(userInput: string) {
  callA(userInput);
  const systemPrompt = `System instructions. Said: ${userInput}`;
  openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "system", content: systemPrompt }],
  });
}
