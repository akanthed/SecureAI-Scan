// Part of a 2-file interprocedural chain: request data flows from ../api.ts
// into this function's parameter, which is interpolated into a system
// prompt right here — the LLM call itself lives in the crossed-into file.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function askWithSystemPrompt(userInput: string) {
  const systemPrompt = `System: do X. User said: ${userInput}`;
  return openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "system", content: systemPrompt }],
  });
}
