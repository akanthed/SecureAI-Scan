import { generateText } from "ai";

// Regression fixture: bare English words that happen to match secret hints
// ("secret", "token") inside ordinary narrative/example prompt text must
// not fire — found via real-world scan of the Vercel AI SDK's examples
// (a fiction-summarization demo using words like "secret" and "hidden").
export async function summarizeStory() {
  return generateText({
    model: "gpt-4o",
    messages: [
      {
        role: "system",
        content:
          "You are an AI assistant tasked with analyzing this story: the old house held many secrets, and the hidden door led to a token of the family's past.",
      },
      { role: "user", content: "What are the key narrative points?" },
    ],
  });
}
