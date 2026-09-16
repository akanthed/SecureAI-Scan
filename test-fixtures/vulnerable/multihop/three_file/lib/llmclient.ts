import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function callLlm(userInput: string) {
  const systemPrompt = `System: do X. User said: ${userInput}`;
  return openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "system", content: systemPrompt }],
  });
}
