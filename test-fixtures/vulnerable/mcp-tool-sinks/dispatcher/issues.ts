import { execAsync } from "./exec-util.js";

export async function commentOnIssue(params: { repo: string; issue: number }) {
  const { stdout } = await execAsync(`gh issue comment ${params.issue} --repo ${params.repo} --body-file note.md`);
  return { content: [{ type: "text", text: stdout }] };
}
