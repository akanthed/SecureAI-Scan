import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import {
  getNodeLine,
  getRelativeFilePath,
  isStringConcatenation,
} from "../../utils/ast.js";
import { calculateConfidence } from "../confidence.js";

const LLM_CALLEE_PATTERNS = [
  "openai",
  "anthropic",
  "google",
  "gemini",
  "genai",
];

function isLikelyLlmCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const expressionText = node.getExpression().getText().toLowerCase();
  return LLM_CALLEE_PATTERNS.some((pattern) => expressionText.includes(pattern));
}

function getPromptArguments(node: Node): Node[] {
  if (!Node.isCallExpression(node)) {
    return [];
  }

  const args = node.getArguments();
  if (args.length === 0) {
    return [];
  }

  // Heuristic: first argument or "prompt" property in object literal
  const firstArg = args[0];
  if (Node.isObjectLiteralExpression(firstArg)) {
    const promptProp = firstArg
      .getProperties()
      .find(
        (prop) =>
          Node.isPropertyAssignment(prop) &&
          prop.getNameNode().getText().replace(/['"]/g, "") === "prompt",
      );
    if (promptProp && Node.isPropertyAssignment(promptProp)) {
      return [promptProp.getInitializerOrThrow()];
    }
    return [];
  }

  return [firstArg];
}

function isTemplateLiteral(node: Node): boolean {
  return (
    Node.isTemplateExpression(node) ||
    Node.isNoSubstitutionTemplateLiteral(node)
  );
}

function isRequestObjectAccess(node: Node): boolean {
  if (!Node.isPropertyAccessExpression(node)) {
    return false;
  }
  const root = node.getExpression();
  if (!Node.isIdentifier(root)) {
    return false;
  }
  const rootName = root.getText().toLowerCase();
  if (rootName === "req" || rootName === "request") {
    return true;
  }
  if (rootName === "ctx") {
    const fullText = node.getText().toLowerCase();
    return fullText.startsWith("ctx.request");
  }
  return false;
}

function collectTaintedIdentifiers(node: Node): {
  tainted: Set<string>;
  fromParams: Set<string>;
  fromRequest: Set<string>;
} {
  const tainted = new Set<string>();
  const fromParams = new Set<string>();
  const fromRequest = new Set<string>();

  if (
    Node.isFunctionDeclaration(node) ||
    Node.isFunctionExpression(node) ||
    Node.isArrowFunction(node) ||
    Node.isMethodDeclaration(node)
  ) {
    for (const param of node.getParameters()) {
      const nameNode = param.getNameNode();
      if (Node.isIdentifier(nameNode)) {
        tainted.add(nameNode.getText());
        fromParams.add(nameNode.getText());
      }
    }
  }

  for (const decl of node.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const initializer = decl.getInitializer();
    if (!initializer) {
      continue;
    }
    if (Node.isIdentifier(initializer) && tainted.has(initializer.getText())) {
      tainted.add(decl.getName());
      if (fromParams.has(initializer.getText())) {
        fromParams.add(decl.getName());
      }
      if (fromRequest.has(initializer.getText())) {
        fromRequest.add(decl.getName());
      }
      continue;
    }
    if (isRequestObjectAccess(initializer)) {
      tainted.add(decl.getName());
      fromRequest.add(decl.getName());
    }
  }

  return { tainted, fromParams, fromRequest };
}

function promptContainsTaintedIdentifiers(
  promptNode: Node,
  tainted: Set<string>,
): boolean {
  const identifiers = promptNode.getDescendantsOfKind(SyntaxKind.Identifier);
  return identifiers.some((id) => tainted.has(id.getText()));
}

export const rulePromptInjectionConcat: Rule = {
  id: "AI001",
  title: "Prompt injection via user input",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      // Example detection logic:
      // 1) Mark function parameters + request-derived values as tainted
      // 2) If a prompt is built via concatenation/template literal and references tainted data -> flag
      for (const functionNode of sourceFile.getDescendants()) {
        if (
          !Node.isFunctionDeclaration(functionNode) &&
          !Node.isFunctionExpression(functionNode) &&
          !Node.isArrowFunction(functionNode) &&
          !Node.isMethodDeclaration(functionNode)
        ) {
          continue;
        }

        const taintedInfo = collectTaintedIdentifiers(functionNode);
        if (taintedInfo.tainted.size === 0) {
          continue;
        }

        const calls = functionNode.getDescendantsOfKind(
          SyntaxKind.CallExpression,
        );

        for (const call of calls) {
          if (!isLikelyLlmCall(call)) {
            continue;
          }

          const promptArgs = getPromptArguments(call);
          for (const arg of promptArgs) {
            const isConcatenation = isStringConcatenation(arg);
            const isTemplate = isTemplateLiteral(arg);
            if (!isConcatenation && !isTemplate) {
              continue;
            }

            if (!promptContainsTaintedIdentifiers(arg, taintedInfo.tainted)) {
              continue;
            }

            const identifiers = arg.getDescendantsOfKind(SyntaxKind.Identifier);
            const hasParamInput = identifiers.some((id) =>
              taintedInfo.fromParams.has(id.getText()),
            );
            const hasRequestInput = identifiers.some((id) =>
              taintedInfo.fromRequest.has(id.getText()),
            );

            findings.push({
              rule_id: "AI001",
              title: "Prompt injection via user input",
              severity: "high",
              file: getRelativeFilePath(context.rootPath, sourceFile),
              line: getNodeLine(arg),
              summary: "User input is concatenated into a prompt.",
              description: "User input flows directly into LLM prompt",
              recommendation: "Use role separation and input encoding",
              confidence: calculateConfidence({
                directUserInput: hasParamInput,
                requestObjectSource: hasRequestInput,
                stringConcatOrTemplate: true,
                confirmedLlmCall: true,
              }),
            });
          }
        }
      }
    }

    return findings;
  },
};
