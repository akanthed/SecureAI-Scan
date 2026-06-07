import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isTestFilePath } from "../confidence.js";

// Language commonly used in prompt injection / jailbreak payloads
const INJECTION_PHRASES = [
  "ignore previous",
  "ignore above",
  "ignore all previous",
  "disregard previous",
  "forget previous",
  "override instructions",
  "new instructions",
  "act as",
  "you are now",
  "system prompt",
  "developer mode",
  "jailbreak",
  "do anything now",
  "dan mode",
  "ignore your",
  "bypass",
];

// Contexts that indicate this is a tool/function definition description
const TOOL_CONTEXT_PROPS = ["description", "toolDescription", "functionDescription", "tool_description"];

function containsInjectionPhrase(text: string): string | undefined {
  const lower = text.toLowerCase();
  return INJECTION_PHRASES.find((phrase) => lower.includes(phrase));
}

function isInToolDefinitionContext(node: Node): boolean {
  // Walk up: look for enclosing object that has "name" or "function" props typical of tool defs
  let current: Node | undefined = node.getParent();
  let depth = 0;
  while (current && depth < 5) {
    if (Node.isObjectLiteralExpression(current)) {
      const props = current.getProperties().map((p) => {
        if (Node.isPropertyAssignment(p)) return p.getNameNode().getText().replace(/['"]/g, "").toLowerCase();
        return "";
      });
      const isToolObj =
        props.includes("name") ||
        props.includes("function") ||
        props.includes("parameters") ||
        props.includes("inputschema") ||
        props.includes("input_schema");
      if (isToolObj) return true;
    }
    current = current.getParent();
    depth++;
  }
  return false;
}

export const ruleMcpToolDescInjection: Rule = {
  id: "MCP001",
  title: "MCP tool description contains injection language",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);
      if (isTest) continue; // Tool definitions don't live in test files

      // Check all string literals in the file
      for (const strLiteral of sourceFile.getDescendantsOfKind(SyntaxKind.StringLiteral)) {
        const text = strLiteral.getLiteralText();
        const matchedPhrase = containsInjectionPhrase(text);
        if (!matchedPhrase) continue;

        // Check if the parent property is a description-like field
        const parent = strLiteral.getParent();
        if (!Node.isPropertyAssignment(parent)) continue;

        const propName = parent.getNameNode().getText().replace(/['"]/g, "").toLowerCase();
        if (!TOOL_CONTEXT_PROPS.map((p) => p.toLowerCase()).includes(propName)) continue;

        if (!isInToolDefinitionContext(strLiteral)) continue;

        findings.push({
          rule_id: "MCP001",
          title: "MCP tool description contains injection language",
          severity: "critical",
          file: relPath,
          line: getNodeLine(strLiteral),
          summary: `Tool description contains injection phrase: "${matchedPhrase}".`,
          description:
            "Tool descriptions are sent to the LLM as part of its context. A malicious or compromised MCP server can include override instructions in a tool description, hijacking the model's behavior for all subsequent calls in the session.",
          recommendation:
            "Audit all tool descriptions for injection language. Use an allowlist-based validator on tool descriptions before registering them. For third-party MCP servers, verify the server's integrity and pin to a known-good version.",
          confidence: 0.95,
        });
      }

      // Also check template literals (less common but possible)
      for (const tmpl of sourceFile.getDescendantsOfKind(SyntaxKind.NoSubstitutionTemplateLiteral)) {
        const text = tmpl.getLiteralText();
        const matchedPhrase = containsInjectionPhrase(text);
        if (!matchedPhrase) continue;

        const parent = tmpl.getParent();
        if (!Node.isPropertyAssignment(parent)) continue;

        const propName = parent.getNameNode().getText().replace(/['"]/g, "").toLowerCase();
        if (!TOOL_CONTEXT_PROPS.map((p) => p.toLowerCase()).includes(propName)) continue;

        findings.push({
          rule_id: "MCP001",
          title: "MCP tool description contains injection language",
          severity: "critical",
          file: relPath,
          line: getNodeLine(tmpl),
          summary: `Tool description contains injection phrase: "${matchedPhrase}".`,
          description:
            "Tool descriptions are sent to the LLM as part of its context. A malicious or compromised MCP server can include override instructions in a tool description, hijacking the model's behavior for all subsequent calls in the session.",
          recommendation:
            "Audit all tool descriptions for injection language. Use an allowlist-based validator on tool descriptions before registering them. For third-party MCP servers, verify the server's integrity and pin to a known-good version.",
          confidence: 0.9,
        });
      }
    }

    return findings;
  },
};
