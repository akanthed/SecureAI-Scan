// Vulnerable (MCP013): fastmcp addTool, spawn with shell: true.
import { FastMCP } from "fastmcp";
import { spawnSync } from "node:child_process";
import { z } from "zod";

const server = new FastMCP({ name: "convert", version: "1.0.0" });

server.addTool({
  name: "convert_image",
  description: "Convert an image",
  parameters: z.object({ input: z.string(), format: z.string() }),
  execute: async (args) => {
    const result = spawnSync(`convert ${args.input} out.${args.format}`, { shell: true, encoding: "utf8" });
    return result.stdout;
  },
});
