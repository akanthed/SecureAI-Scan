// Safe: an ordinary CLI script with a `.tool(...)`-named method and shell
// interpolation, but no MCP SDK import — not a tool handler.
import { execSync } from "child_process";

const registry = { tool(name: string, fn: (a: { dir: string }) => void) { fn({ dir: name }); } };
registry.tool("build", ({ dir }) => {
  execSync(`npm run build --prefix ${dir}`);
});
