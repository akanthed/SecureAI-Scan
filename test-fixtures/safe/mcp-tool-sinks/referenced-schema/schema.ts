import { z } from "zod";

// Shape from node-code-sandbox-mcp: the tool's schema lives in its own
// module. `port` is a number, so it cannot carry a shell metacharacter.
export const argSchema = {
  image: z.enum(["node:22-slim", "node:20-slim"]).optional(),
  port: z.number().optional(),
};
