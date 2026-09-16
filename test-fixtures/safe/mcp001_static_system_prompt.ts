// Safe: a static system-prompt string that merely *mentions* the English
// word "tools" while a same-scope variable happens to be named `toolSet` —
// no template interpolation, no dataflow from the MCP listing call into the
// prompt at all. Found scanning cloudflare/mcp-server-cloudflare's
// packages/eval-tools/src/runTask.ts: MCP001 fired `proven`/critical because
// the check compared the prompt's raw source text against the tainted
// variable name with a plain substring search, and "...use the tools
// available to you..." contains "tools" as ordinary prose, not as a
// reference to the `toolSet` variable.
import { generateText } from "ai";

declare const mcpClient: { listTools(): Promise<Array<{ name: string; description: string }>> };

export async function runTask() {
  const toolSet = await mcpClient.listTools();

  await generateText({
    model: "gpt-4.1",
    system:
      "You are an assistant responsible for evaluating the results of calling various tools. Given the user's query, use the tools available to you to answer the question.",
    tools: toolSet,
  });
}
