import type { CallToolRequest } from "@modelcontextprotocol/sdk/types.js";
import { commentOnIssue } from "./issues.js";

export async function handleToolRequest(request: CallToolRequest) {
  const args = request.params.arguments as Record<string, unknown>;
  switch (request.params.name) {
    case "add_comment":
      return commentOnIssue({
        repo: args.repo as string,
        // Number() can't carry a shell metacharacter: must NOT be what fires.
        issue: Number(args.issue),
      });
    default:
      throw new Error("unknown tool");
  }
}
