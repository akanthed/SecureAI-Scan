// Vulnerable: generateObject's result is schema-validated for shape only —
// the "command" field is guaranteed to be a string, not a safe one. It is
// executed directly with no content check.
import { generateObject } from "ai";
import { openai } from "@ai-sdk/openai";
import { execSync } from "node:child_process";
import { z } from "zod";

const ActionSchema = z.object({ command: z.string() });

export async function runSuggestedAction() {
  const { object } = await generateObject({
    model: openai("gpt-4.1"),
    schema: ActionSchema,
    prompt: "Suggest a shell command to resolve the latest support ticket.",
  });

  execSync(object.command);
}
