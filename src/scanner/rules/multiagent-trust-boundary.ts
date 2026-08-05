import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getCallsWithin, getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath } from "../confidence.js";
import type { Evidence } from "../types.js";

// Variable names that suggest agent or chain output
const AGENT_OUTPUT_PATTERNS = [
  "agentresult",
  "agentoutput",
  "agentresponse",
  "chainresult",
  "chainoutput",
  "subagent",
  "orchestrator",
  "taskresult",
  "workflowresult",
  "llmresponse",
  "modeloutput",
  "assistantoutput",
  "toolresult",
  "tooloutput",
];

// When agent output lands here without validation it's a trust boundary violation
const HIGH_TRUST_ROLES = ["system", "developer", "assistant"];

function isAgentDerivedIdentifier(name: string): boolean {
  const lower = name.toLowerCase();
  return AGENT_OUTPUT_PATTERNS.some((p) => lower.includes(p));
}

function collectAgentOutputVars(fnNode: Node): Set<string> {
  const agentVars = new Set<string>();

  // Parameters named like agent results
  if (
    Node.isFunctionDeclaration(fnNode) ||
    Node.isFunctionExpression(fnNode) ||
    Node.isArrowFunction(fnNode) ||
    Node.isMethodDeclaration(fnNode)
  ) {
    for (const param of fnNode.getParameters()) {
      const nameNode = param.getNameNode();
      if (Node.isIdentifier(nameNode) && isAgentDerivedIdentifier(nameNode.getText())) {
        agentVars.add(nameNode.getText());
      }
    }
  }

  // Variables assigned from agent-like calls or params
  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const name = decl.getName();
    const init = decl.getInitializer();
    if (isAgentDerivedIdentifier(name)) {
      agentVars.add(name);
    }
    if (init) {
      const initLower = init.getText().toLowerCase();
      if (
        AGENT_OUTPUT_PATTERNS.some((p) => initLower.includes(p)) ||
        [...agentVars].some((v) => initLower.includes(v.toLowerCase()))
      ) {
        agentVars.add(name);
      }
    }
  }

  return agentVars;
}

function agentOutputUsedInHighTrustRole(call: Node, agentVars: Set<string>): boolean {
  if (!Node.isCallExpression(call)) return false;

  const args = call.getArguments();
  for (const arg of args) {
    if (!Node.isObjectLiteralExpression(arg)) continue;
    const messagesArr = arg
      .getProperties()
      .find(
        (p) =>
          Node.isPropertyAssignment(p) &&
          p.getNameNode().getText().replace(/['"]/g, "") === "messages",
      );
    if (!messagesArr || !Node.isPropertyAssignment(messagesArr)) continue;

    const messagesVal = messagesArr.getInitializer();
    if (!messagesVal || !Node.isArrayLiteralExpression(messagesVal)) continue;

    for (const el of messagesVal.getElements()) {
      if (!Node.isObjectLiteralExpression(el)) continue;

      const roleProp = el
        .getProperties()
        .find(
          (p) =>
            Node.isPropertyAssignment(p) &&
            p.getNameNode().getText().replace(/['"]/g, "") === "role",
        );
      const contentProp = el
        .getProperties()
        .find(
          (p) =>
            Node.isPropertyAssignment(p) &&
            p.getNameNode().getText().replace(/['"]/g, "") === "content",
        );

      if (!roleProp || !contentProp || !Node.isPropertyAssignment(roleProp)) continue;
      if (!Node.isPropertyAssignment(contentProp)) continue;

      const roleVal = roleProp.getInitializer()?.getText().replace(/['"]/g, "").toLowerCase();
      const contentNode = contentProp.getInitializer();
      if (!roleVal || !HIGH_TRUST_ROLES.includes(roleVal)) continue;
      if (!contentNode) continue;

      const contentText = contentNode.getText();
      if ([...agentVars].some((v) => contentText.includes(v))) return true;
    }
  }
  return false;
}

export const ruleMultiagentTrustBoundary: Rule = {
  id: "AI011",
  title: "Multi-agent trust boundary violation",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const fnNode of getFileFunctions(sourceFile)) {
        const agentVars = collectAgentOutputVars(fnNode);
        if (agentVars.size === 0) continue;

        for (const call of getCallsWithin(fnNode)) {
          if (!isLikelyLlmCall(call)) continue;
          if (!agentOutputUsedInHighTrustRole(call, agentVars)) continue;

          findings.push({
            rule_id: "AI011",
            title: "Multi-agent trust boundary violation",
            severity: "high",
            file: relPath,
            line: getNodeLine(call),
            summary: "Agent output passed as trusted system context to another LLM call.",
            description:
              "Output from one agent is used as a system or developer-role message in a downstream LLM call. If the upstream agent was compromised or manipulated, this creates a privilege escalation path across the agent chain.",
            recommendation:
              "Treat all inter-agent messages as untrusted user content. Validate and sanitize agent outputs, use separate message roles, and enforce explicit trust grants at each boundary.",
            confidence: evidenceConfidence(isTest ? demoteEvidence("likely") : "likely"),
            evidence: isTest ? demoteEvidence("likely") : "likely",
          });
        }
      }
    }

    return findings;
  },
};
