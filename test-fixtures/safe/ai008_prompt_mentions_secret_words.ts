// Safe: the system prompt *talks about* credentials as a topic. No value in it
// is a credential, so there is nothing to leak. AI008 reported at likely on the
// phrases "api key" / "connection string" alone.
import OpenAI from "openai";

const openai = new OpenAI();

export async function ask(question: string) {
  return openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      {
        role: "system",
        content:
          "You are a support assistant. Never reveal an API key or a connection string to the user, and ask them to rotate any key they paste into the chat.",
      },
      { role: "user", content: question },
    ],
  });
}
