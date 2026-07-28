import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence } from "../confidence.js";
import { isLikelyLlmCall, resolveLlmSink } from "./llm-rule-utils.js";

// Note: JSON.parse is intentionally NOT here — parsing structured output is
// normal and is covered by AI012 (unvalidated structured output) instead.
const DANGEROUS_CALLEES = [
  "eval",
  "exec",
  "execsync",
  "spawn",
  "spawnsync",
  "query",
  "raw",
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

  // Propagate through derivations: const code = completion.choices[0].message.content
  let changed = true;
  let passes = 0;
  while (changed && passes < 4) {
    changed = false;
    passes += 1;
    for (const declaration of functionNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      const name = declaration.getName().toLowerCase();
      if (outputs.has(name)) continue;
      const initializer = declaration.getInitializer();
      if (!initializer) continue;
      const derived = initializer
        .getDescendantsOfKind(SyntaxKind.Identifier)
        .some((id) => outputs.has(id.getText().toLowerCase()));
      const direct = Node.isIdentifier(initializer) && outputs.has(initializer.getText().toLowerCase());
      if (derived || direct) {
        outputs.add(name);
        changed = true;
      }
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
  if (!DANGEROUS_CALLEES.some((dangerous) => callee === dangerous || callee.endsWith(`.${dangerous}`))) {
    return false;
  }
  // "query" name-matches a real SQL sink (db.query(sql), pool.query(...))
  // but is also a legitimate LLM/agent invocation verb (claudeSdk.query(...))
  // — found via a false positive on the Claude Agent SDK's own
  // claudeSdk.query() call, which shares the bare verb "query" with
  // GENERATION_METHODS in llm-rule-utils.ts. A call that is
  // import-resolved (or name-hinted) as an LLM invocation in its own right
  // cannot simultaneously be the dangerous sink receiving that LLM's output —
  // reusing the existing resolver here, rather than adding a second
  // independent name heuristic, keeps the exclusion consistent with how the
  // rest of the ruleset already decides what counts as "an LLM call".
  if (resolveLlmSink(call)) {
    return false;
  }
  return true;
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
            confidence: evidenceConfidence("likely"),
            evidence: "likely",
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
            confidence: evidenceConfidence("likely"),
            evidence: "likely",
          });
        }
      }
    }

    return findings;
  },
};

