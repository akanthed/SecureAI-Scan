import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import {
  evidenceConfidence,
  demoteEvidence,
  identifierTokens,
  isTestFilePath,
} from "../confidence.js";
import { getObjectProperty, resolveLlmSink } from "./llm-rule-utils.js";

// High-impact actions only. Generic words (fetch/http/request/write/send)
// matched nearly every real tool list and are deliberately excluded.
const DANGEROUS_TOKENS = new Set([
  "delete",
  "remove",
  "drop",
  "destroy",
  "exec",
  "execute",
  "shell",
  "command",
  "deploy",
  "purchase",
  "payment",
  "refund",
  "transfer",
  "wire",
  "terminate",
]);
const DANGEROUS_TOKEN_PAIRS: Array<[string, string]> = [
  ["send", "email"],
  ["send", "mail"],
  ["send", "sms"],
  ["write", "file"],
  ["run", "sql"],
];

const APPROVAL_TOKENS = new Set([
  "approve",
  "approval",
  "confirm",
  "confirmation",
  "authorize",
  "review",
  "human",
  "hitl",
]);

function extractToolNames(toolsNode: Node): string[] {
  const names: string[] = [];
  // tools: [{ name: "deleteUser", ... }] or { function: { name: "..." } }
  for (const prop of toolsNode.getDescendantsOfKind(SyntaxKind.PropertyAssignment)) {
    const key = prop.getNameNode().getText().replace(/['"]/g, "");
    if (key !== "name") continue;
    const init = prop.getInitializer();
    if (init && (Node.isStringLiteral(init) || Node.isNoSubstitutionTemplateLiteral(init))) {
      names.push(init.getLiteralText());
    }
  }
  // Vercel-style: tools: { deleteUser: tool({...}) }
  if (Node.isObjectLiteralExpression(toolsNode)) {
    for (const prop of toolsNode.getProperties()) {
      if (Node.isPropertyAssignment(prop) || Node.isShorthandPropertyAssignment(prop)) {
        names.push(prop.getName());
      }
    }
  }
  // Bare identifiers in an array: tools: [deleteUserTool]
  if (Node.isArrayLiteralExpression(toolsNode)) {
    for (const el of toolsNode.getElements()) {
      if (Node.isIdentifier(el)) names.push(el.getText());
    }
  }
  return names;
}

function isDangerousName(name: string): boolean {
  const tokens = identifierTokens(name);
  if (tokens.some((t) => DANGEROUS_TOKENS.has(t))) return true;
  const set = new Set(tokens);
  return DANGEROUS_TOKEN_PAIRS.some(([a, b]) => set.has(a) && set.has(b));
}

function hasApprovalGate(text: string): boolean {
  const words = text.split(/[^A-Za-z]+/);
  for (const word of words) {
    if (identifierTokens(word).some((t) => APPROVAL_TOKENS.has(t))) return true;
  }
  return false;
}

export const ruleExcessiveAgency: Rule = {
  id: "AI006",
  title: "Excessive LLM agency",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);

      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        const sink = resolveLlmSink(call);
        if (!sink) continue;

        const firstArg = call.getArguments()[0];
        if (!firstArg || !Node.isObjectLiteralExpression(firstArg)) continue;
        const toolConfig =
          getObjectProperty(firstArg, "tools") ?? getObjectProperty(firstArg, "functions");
        if (!toolConfig) continue;

        const toolNames = extractToolNames(toolConfig);
        const dangerous = toolNames.filter(isDangerousName);
        if (dangerous.length === 0) continue;

        const enclosingFunction = call.getFirstAncestor(
          (a) =>
            Node.isFunctionDeclaration(a) ||
            Node.isFunctionExpression(a) ||
            Node.isArrowFunction(a) ||
            Node.isMethodDeclaration(a),
        );
        const scopeText = enclosingFunction?.getText() ?? sourceFile.getFullText();
        if (hasApprovalGate(scopeText)) continue;

        let evidence: Evidence = sink.resolved ? "likely" : "heuristic";
        if (testFile) evidence = demoteEvidence(evidence);

        findings.push({
          rule_id: "AI006",
          title: "Excessive LLM agency",
          severity: "critical",
          file: relFile,
          line: getNodeLine(toolConfig),
          summary: `Model can invoke high-impact tool(s) ${dangerous.map((d) => `\`${d}\``).join(", ")} with no approval gate in scope.`,
          description:
            `The ${sink.provider} call exposes tools whose names indicate irreversible or costly actions (${dangerous.join(", ")}). A prompt-injection payload anywhere in the model's context can trigger these tools; no human-approval or confirmation logic is visible in the surrounding code.`,
          recommendation:
            "Gate high-impact tools behind explicit confirmation (human-in-the-loop) or a policy check on the tool-call arguments before execution. Log every tool invocation with its triggering context.",
          confidence: evidenceConfidence(evidence),
          evidence,
        });
      }
    }

    return findings;
  },
};
