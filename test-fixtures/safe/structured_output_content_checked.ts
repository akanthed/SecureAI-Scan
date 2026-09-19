// Safe: generateObject's result is schema-validated for shape, AND the
// "command" field's content is checked against an allowlist before it is
// ever passed to execSync. Locks in that AI013 doesn't fire once a real
// content check exists, not just the schema's shape check.
import { generateObject } from "ai";
import { openai } from "@ai-sdk/openai";
import { execSync } from "node:child_process";
import { z } from "zod";

const ActionSchema = z.object({ command: z.string() });

const ALLOWLIST = new Set(["restart-service", "clear-cache"]);

export async function runSuggestedAction() {
  const { object } = await generateObject({
    model: openai("gpt-4.1"),
    schema: ActionSchema,
    prompt: "Suggest a shell command to resolve the latest support ticket.",
  });

  if (!ALLOWLIST.has(object.command)) throw new Error("Rejected: not an allowed command");
  execSync(object.command);
}
