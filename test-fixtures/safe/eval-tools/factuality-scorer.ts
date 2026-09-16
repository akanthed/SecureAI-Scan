// Safe: an LLM-as-judge eval-harness scorer, not a request handler. Found
// scanning cloudflare/mcp-server-cloudflare's packages/eval-tools/src/scorers.ts
// (vitest-evals): interpolating a benchmark case's input/expected/output triple
// into a grading prompt is the standard shape of an eval scorer, structurally
// identical to real prompt injection but not fed by untrusted request data.
// The "eval-tools" path segment now demotes it the same way "tests/"/"examples/" do.
import { generateObject } from "ai";
import { factualityModel } from "./test-models";

export const checkFactuality = async ({
  input,
  expected,
  output,
}: {
  input: string;
  expected: string;
  output: string;
}) => {
  const { object } = await generateObject({
    model: factualityModel,
    prompt: `
      Compare the submitted answer to the expert rubric.
      [Question]: ${input}
      [Expert Rubric]: ${expected}
      [Submission]: ${output}
    `,
  });
  return object;
};
