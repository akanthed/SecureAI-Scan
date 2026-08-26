import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handleChat(req: { body: { input: string } }) {
  const userInput = req.body.input;
  const systemPrompt = "You are a helpful assistant. " + userInput;

  return openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: userInput },
    ],
  });
}
