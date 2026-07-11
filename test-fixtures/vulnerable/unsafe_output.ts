// Vulnerable: LLM output flows into eval().
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function runGeneratedCode(req: { body: { task: string } }) {
  requireAuth(req);
  const completion = await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: "Write JS for: task" }],
  });

  const code = completion.choices[0].message.content ?? "";
  // eslint-disable-next-line no-eval
  eval(code);
}

function requireAuth(req: unknown): void {
  if (!req) throw new Error("Unauthorized");
}
