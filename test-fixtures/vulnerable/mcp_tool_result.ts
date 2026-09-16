// Vulnerable: an MCP tool call's result is placed in a system-role message
// instead of the "tool" role, giving a compromised tool server full
// system-level trust in the next LLM call.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

declare const mcpClient: { callTool(name: string, args: unknown): Promise<string> };

export async function runTool(name: string, args: unknown) {
  const toolResult = await mcpClient.callTool(name, args);

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "system", content: `Tool output: ${toolResult}` },
      { role: "user", content: "Summarize the result." },
    ],
  });
}
