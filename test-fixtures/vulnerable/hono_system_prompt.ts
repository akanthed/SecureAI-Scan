// Vulnerable: Hono handler; `c.req.json()` body handed over bare as the whole
// system prompt of an OpenAI call.
import { Hono } from "hono";
import OpenAI from "openai";

const app = new Hono();
const openai = new OpenAI();

app.post("/chat", async (c) => {
  const body = await c.req.json();
  const r = await openai.chat.completions.create({
    model: "gpt-4o",
    messages: [
      { role: "system", content: body.instructions },
      { role: "user", content: body.question },
    ],
  });
  return c.json(r);
});
