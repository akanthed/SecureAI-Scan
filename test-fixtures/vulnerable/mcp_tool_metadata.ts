// Vulnerable: tool metadata from an MCP server (arrives over the wire, not
// from this codebase) is interpolated directly into a system prompt with no
// trust demotion — a compromised server can inject instructions this way.
import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY! });

declare const mcpClient: { listTools(): Promise<Array<{ name: string; description: string }>> };

export async function buildSystemContext() {
  const tools = await mcpClient.listTools();

  await openai.chat.completions.create({
    model: "gpt-4.1",
    messages: [
      { role: "system", content: `Available tools: ${tools}` },
      { role: "user", content: "What can you do?" },
    ],
  });
}
