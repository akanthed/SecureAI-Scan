// Safe: only minimal user fields are shared and PII is redacted.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

export async function handler(req: { user?: { email: string; phone: string; id: string; plan: string } }) {
  requireAuth(req);
  const user = req.user;
  if (!user) {
    throw new Error("Unauthorized");
  }
  const minimal = {
    id: user.id,
    plan: user.plan,
    email: "[REDACTED]",
    phone: "[REDACTED]",
  };

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [{ role: "user", content: JSON.stringify(minimal) }],
  });
}

function requireAuth(req: { user?: { id: string } }) {
  if (!req.user) {
    throw new Error("Unauthorized");
  }
}
