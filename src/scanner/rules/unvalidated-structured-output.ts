import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath } from "../confidence.js";

// Schema validation libraries / patterns that indicate safe usage
const VALIDATION_PATTERNS = [
  "zod",
  "yup",
  "joi",
  ".validate(",
  ".safeParse(",
  "ajv",
  "schema",
  "jsonschema",
  ".assert(",
  "typeguard",
  "is(",
];

// Bare ".parse(" is a genuine schema-validation signal (myValidator.parse(x)),
// but as a plain substring it also matches JSON.parse( itself — the exact
// call this rule flags always appears in the same function, in the same
// text, as the "safe" pattern that's supposed to suppress it. That made this
// rule unfireable on its own target pattern. A negative lookbehind excludes
// the JSON.parse case specifically while still catching real .parse() calls.
const GENERIC_PARSE_PATTERN = /(?<!json)\.parse\(/;

interface ResponseOrigin {
  line: number;
  note: string;
}

function collectLlmResponseVars(fnNode: Node): Map<string, ResponseOrigin> {
  const vars = new Map<string, ResponseOrigin>();

  for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    if (!isLikelyLlmCall(call)) continue;
    // Find the variable the call result is assigned to
    const parent = call.getParent();
    let declNode: Node | undefined;
    if (Node.isVariableDeclaration(parent)) {
      declNode = parent;
    } else if (Node.isAwaitExpression(parent)) {
      const grandParent = parent.getParent();
      if (Node.isVariableDeclaration(grandParent)) declNode = grandParent;
    }
    if (declNode && Node.isVariableDeclaration(declNode)) {
      const name = declNode.getName();
      vars.set(name, { line: getNodeLine(declNode), note: `LLM response \`${name}\`` });
    }
  }

  // Propagate through property accesses: content = response.choices[0].message.content
  // Iterate to a fixed point so multi-hop chains (a = llmCall(); b = a.x; c = b.y)
  // are all captured, without ever adding a var on name alone. The origin
  // carried forward stays the earliest LLM-call assignment in the chain.
  let changed = true;
  while (changed) {
    changed = false;
    for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      if (vars.has(decl.getName())) continue;
      const init = decl.getInitializer();
      if (!init) continue;
      const initText = init.getText();
      const parentKey = [...vars.keys()].find(
        (v) => initText.startsWith(v + ".") || initText.startsWith(v + "["),
      );
      if (parentKey) {
        vars.set(decl.getName(), vars.get(parentKey)!);
        changed = true;
      }
    }
  }

  return vars;
}

function hasSchemaValidationNearby(fnNode: Node): boolean {
  const fnText = fnNode.getText().toLowerCase();
  return (
    VALIDATION_PATTERNS.some((p) => fnText.includes(p.toLowerCase())) ||
    GENERIC_PARSE_PATTERN.test(fnText)
  );
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
          const matched = [...llmVars.keys()].find((v) => argText.includes(v));
          if (!matched) continue;
          const origin = llmVars.get(matched)!;
          const sinkLine = getNodeLine(call);

          const trace: TraceStep[] = [
            { kind: "source", file: relPath, line: origin.line, note: origin.note },
            { kind: "sink", file: relPath, line: sinkLine, note: "JSON.parse(...) with no schema validation" },
          ];

          findings.push({
            rule_id: "AI012",
            title: "LLM output used as structured data without schema validation",
            severity: "medium",
            file: relPath,
            line: sinkLine,
            summary: "LLM response parsed with JSON.parse without a schema validator.",
            description:
              "LLM outputs are non-deterministic. Parsing them directly as structured data without a schema (Zod, Yup, Joi, etc.) allows unexpected shapes, missing fields, or injected keys to propagate silently into application logic.",
            recommendation:
              "Validate parsed JSON against a strict schema (e.g. z.object({...}).parse(JSON.parse(raw))). Consider using structured output mode (response_format: { type: 'json_schema' }) to constrain model output at the API level.",
            confidence: evidenceConfidence(isTest ? demoteEvidence("likely") : "likely"),
            evidence: isTest ? demoteEvidence("likely") : "likely",
            trace,
          });
        }
      }
    }

    return findings;
  },
};
