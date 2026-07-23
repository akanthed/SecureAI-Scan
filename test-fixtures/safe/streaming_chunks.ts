import OpenAI from "openai";

// Regression fixture: "chunks" is a common streaming-response variable name
// (`for await (const chunk of stream)`) with nothing to do with RAG. Found
// via real-world scan of the OpenAI Node SDK's own test/example code.
const openai = new OpenAI();

export async function streamAnswer() {
  const stream = await openai.chat.completions.create({
    messages: [{ role: "system", content: "You are a helpful assistant." }],
    stream: true,
  });

  const chunks: string[] = [];
  for await (const part of stream) {
    chunks.push(part.choices[0]?.delta?.content ?? "");
  }
  return chunks.join("");
}
