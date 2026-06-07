import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { calculateConfidence, isTestFilePath } from "../confidence.js";

// Names that typically hold LLM response content
const LLM_RESPONSE_PATTERNS = [
  "response",
  "completion",
  "result",
  "output",
  "answer",
  "reply",
  "llmresult",
  "chatresult",
  "generated",
];

// Schema validation libraries / patterns that indicate safe usage
const VALIDATION_PATTERNS = [
  "zod",
  "yup",
  "joi",
  ".parse(",
  ".validate(",
  ".safeParse(",
  "ajv",
  "schema",
  "jsonschema",
  ".assert(",
  "typeguard",
  "is(",
];

function isLlmResponseVar(name: string): boolean {
  const lower = name.toLowerCase();
  return LLM_RESPONSE_PATTERNS.some((p) => lower.includes(p));
}

function collectLlmResponseVars(fnNode: Node): Set<string> {
  const vars = new Set<string>();

  for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    if (!isLikelyLlmCall(call)) continue;
    // Find the variable the call result is assigned to
    const parent = call.getParent();
    if (Node.isVariableDeclaration(parent)) {
      vars.add(parent.getName());
    }
    if (Node.isAwaitExpression(parent)) {
      const grandParent = parent.getParent();
      if (Node.isVariableDeclaration(grandParent)) {
        vars.add(grandParent.getName());
      }
    }
  }

  // Propagate through property accesses: content = response.choices[0].message.content
  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init) continue;
    const initText = init.getText();
    if ([...vars].some((v) => initText.startsWith(v + ".") || initText.startsWith(v + "["))) {
      vars.add(decl.getName());
    }
    if (isLlmResponseVar(decl.getName())) {
      vars.add(decl.getName());
    }
  }

  return vars;
}

function hasSchemaValidationNearby(fnNode: Node): boolean {
  const fnText = fnNode.getText().toLowerCase();
  return VALIDATION_PATTERNS.some((p) => fnText.includes(p.toLowerCase()));
}

export const ruleUnvalidatedStructuredOutput: Rule = {
  id: "AI012",
  title: "LLM output used as structured data without schema validation",
  severity: "medium",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const fnNode of sourceFile.getDescendants()) {
        if (
          !Node.isFunctionDeclaration(fnNode) &&
          !Node.isFunctionExpression(fnNode) &&
          !Node.isArrowFunction(fnNode) &&
          !Node.isMethodDeclaration(fnNode)
        ) continue;

        const llmVars = collectLlmResponseVars(fnNode);
        if (llmVars.size === 0) continue;

        if (hasSchemaValidationNearby(fnNode)) continue;

        // Look for JSON.parse of LLM response vars
        for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
          const exprText = call.getExpression().getText().toLowerCase();
          if (exprText !== "json.parse") continue;

          const argText = call.getArguments()[0]?.getText() ?? "";
          if (![...llmVars].some((v) => argText.includes(v))) continue;

          findings.push({
            rule_id: "AI012",
            title: "LLM output used as structured data without schema validation",
            severity: "medium",
            file: relPath,
            line: getNodeLine(call),
            summary: "LLM response parsed with JSON.parse without a schema validator.",
            description:
              "LLM outputs are non-deterministic. Parsing them directly as structured data without a schema (Zod, Yup, Joi, etc.) allows unexpected shapes, missing fields, or injected keys to propagate silently into application logic.",
            recommendation:
              "Validate parsed JSON against a strict schema (e.g. z.object({...}).parse(JSON.parse(raw))). Consider using structured output mode (response_format: { type: 'json_schema' }) to constrain model output at the API level.",
            confidence: calculateConfidence({
              confirmedLlmCall: true,
              multipleSignals: true,
              isTestFile: isTest,
            }),
          });
        }
      }
    }

    return findings;
  },
};
