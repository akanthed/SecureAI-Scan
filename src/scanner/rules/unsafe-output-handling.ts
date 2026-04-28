import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { calculateConfidence } from "../confidence.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";

const DANGEROUS_CALLEES = [
  "eval",
  "function",
  "exec",
  "execsync",
  "spawn",
  "spawnsync",
  "query",
  "raw",
  "json.parse",
];

function collectLlmOutputIdentifiers(functionNode: Node): Set<string> {
  const outputs = new Set<string>();

  for (const declaration of functionNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const initializer = declaration.getInitializer();
    if (!initializer) {
      continue;
    }
    if (
      isLikelyLlmCall(initializer) ||
      initializer
        .getDescendantsOfKind(SyntaxKind.CallExpression)
        .some(isLikelyLlmCall)
    ) {
      outputs.add(declaration.getName().toLowerCase());
    }
  }

  return outputs;
}

function callUsesLlmOutput(call: Node, llmOutputs: Set<string>): boolean {
  if (!Node.isCallExpression(call)) {
    return false;
  }
  return call
    .getArguments()
    .some((arg) =>
      arg
        .getDescendantsOfKind(SyntaxKind.Identifier)
        .some((identifier) => llmOutputs.has(identifier.getText().toLowerCase())) ||
      (Node.isIdentifier(arg) && llmOutputs.has(arg.getText().toLowerCase())),
    );
}

function isDangerousSink(call: Node): boolean {
  if (!Node.isCallExpression(call)) {
    return false;
  }
  const callee = call.getExpression().getText().toLowerCase();
  return DANGEROUS_CALLEES.some((dangerous) => callee === dangerous || callee.endsWith(`.${dangerous}`));
}

function isInnerHtmlAssignment(node: Node, llmOutputs: Set<string>): boolean {
  if (!Node.isBinaryExpression(node)) {
    return false;
  }
  const left = node.getLeft().getText().toLowerCase();
  if (!left.endsWith(".innerhtml") && !left.endsWith(".outerhtml")) {
    return false;
  }
  return node
    .getRight()
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((identifier) => llmOutputs.has(identifier.getText().toLowerCase()));
}

export const ruleUnsafeOutputHandling: Rule = {
  id: "AI005",
  title: "Unsafe LLM output handling",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      for (const functionNode of sourceFile.getDescendants()) {
        if (
          !Node.isFunctionDeclaration(functionNode) &&
          !Node.isFunctionExpression(functionNode) &&
          !Node.isArrowFunction(functionNode) &&
          !Node.isMethodDeclaration(functionNode)
        ) {
          continue;
        }

        const llmOutputs = collectLlmOutputIdentifiers(functionNode);
        if (llmOutputs.size === 0) {
          continue;
        }

        for (const call of functionNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
          if (!isDangerousSink(call) || !callUsesLlmOutput(call, llmOutputs)) {
            continue;
          }
          findings.push({
            rule_id: "AI005",
            title: "Unsafe LLM output handling",
            severity: "critical",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(call),
            summary: "LLM output is passed to a dangerous sink.",
            description:
              "Model output flows into code execution, command execution, database, HTML, or parser behavior without an obvious validation boundary.",
            recommendation:
              "Validate model output against a strict schema and keep it away from eval, shell, SQL, HTML, and dynamic execution sinks.",
            confidence: calculateConfidence({
              directUserInput: false,
              requestObjectSource: false,
              stringConcatOrTemplate: false,
              confirmedLlmCall: true,
            }),
          });
        }

        for (const assignment of functionNode.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
          if (!isInnerHtmlAssignment(assignment, llmOutputs)) {
            continue;
          }
          findings.push({
            rule_id: "AI005",
            title: "Unsafe LLM output handling",
            severity: "critical",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(assignment),
            summary: "LLM output is assigned to HTML.",
            description:
              "Model output is rendered as HTML without an obvious sanitizer, which can turn prompt output into script execution.",
            recommendation:
              "Render model output as text or sanitize it with a proven HTML sanitizer before assigning it to DOM HTML sinks.",
            confidence: 0.7,
          });
        }
      }
    }

    return findings;
  },
};

