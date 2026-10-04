// Regression fixture: from vercel/ai's examples
// (examples/ai-e2e-next/app/api/use-object*/route.ts,
// examples/sveltekit-openai/.../structured-object/+server.ts). Request data
// composed into the Vercel AI SDK `prompt` field is the user's own message:
// static instructions live in `system`, or there are none to override.
// Reported as likely AI001 once `await req.json()` was tainted.
import { streamText, Output } from "ai";
import { z } from "zod";
import { auth } from "./auth";

const expenseSchema = z.object({ category: z.string(), amount: z.number() });

export async function POST(req: Request) {
  await auth();
  const { expense } = await req.json();
  const result = streamText({
    model: "openai/gpt-4o",
    system: "You categorize expenses into TRAVEL, MEALS, ENTERTAINMENT, OFFICE SUPPLIES, OTHER.",
    prompt: `Please categorize the following expense: "${expense}"`,
    output: Output.object({ schema: expenseSchema }),
  });
  return result.toTextStreamResponse();
}

export async function PUT(request: Request) {
  await auth();
  const context = await request.json();
  const result = streamText({
    model: "openai/gpt-4o",
    prompt: `Generate 3 notifications for a messages app in this context: ${context}`,
  });
  return result.toTextStreamResponse();
}
