// Vulnerable: a subagent's output is elevated to a system-role message in a
// downstream LLM call, with no validation between the two agents.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

async function runSubagent(task: string): Promise<string> {
  return `result for ${task}`;
}

export async function orchestrate(task: string) {
  const agentResult = await runSubagent(task);

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "system", content: `Prior agent findings: ${agentResult}` },
      { role: "user", content: "Continue the workflow." },
    ],
  });
}
