import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath } from "../confidence.js";
import { getPromptParts, resolveLlmSink } from "./llm-rule-utils.js";

const SENSITIVE_OBJECT_NAMES = new Set([
  "user",
  "profile",
  "session",
  "account",
  "customer",
  "member",
  "patient",
  "employee",
]);

function isJsonStringify(node: Node): node is import("ts-morph").CallExpression {
  if (!Node.isCallExpression(node)) return false;
  const text = node.getExpression().getText();
  return text === "JSON.stringify";
}

/**
 * True when the serialized value is a whole sensitive object — a bare
 * identifier (user), property access (req.user), or an object literal that
 * spreads one (...user). Explicitly-built object literals with picked or
 * redacted fields are the SAFE pattern and must not be flagged.
 */
function serializesWholeSensitiveObject(arg: Node): { label: string } | undefined {
  if (Node.isIdentifier(arg) && SENSITIVE_OBJECT_NAMES.has(arg.getText().toLowerCase())) {
    return { label: arg.getText() };
  }
  if (Node.isPropertyAccessExpression(arg)) {
    const name = arg.getName().toLowerCase();
    if (SENSITIVE_OBJECT_NAMES.has(name)) return { label: arg.getText() };
  }
  if (Node.isObjectLiteralExpression(arg)) {
    for (const prop of arg.getProperties()) {
      if (Node.isSpreadAssignment(prop)) {
        const inner = prop.getExpression();
        const found = serializesWholeSensitiveObject(inner);
        if (found) return { label: `{ ...${found.label} }` };
      }
    }
  }
  return undefined;
}

export const ruleSensitiveDataToLlm: Rule = {
  id: "AI004",
  title: "Sensitive data sent to LLM",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);

      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        const sink = resolveLlmSink(call);
        if (!sink) continue;

        for (const part of getPromptParts(call)) {
          const candidates: Node[] = [part.node, ...part.node.getDescendantsOfKind(SyntaxKind.CallExpression)];
          for (const candidate of candidates) {
            if (!isJsonStringify(candidate)) continue;
            const serialized = candidate.getArguments()[0];
            if (!serialized) continue;

            // Resolve identifier → its declaration to see what is serialized.
            let target: Node = serialized;
            if (Node.isIdentifier(serialized) && !SENSITIVE_OBJECT_NAMES.has(serialized.getText().toLowerCase())) {
              const decl = serialized
                .getSymbol()
                ?.getDeclarations()
                .find(Node.isVariableDeclaration);
              const init = decl?.getInitializer();
              // A locally-built object literal (field picking / redaction)
              // is the recommended remediation — skip it.
              if (init && Node.isObjectLiteralExpression(init)) {
                const spread = serializesWholeSensitiveObject(init);
                if (!spread) continue;
                target = init;
              } else if (!init) {
                continue;
              } else {
                target = init;
              }
            }

            const whole = serializesWholeSensitiveObject(target);
            if (!whole) continue;

            let evidence: Evidence = sink.resolved ? "likely" : "heuristic";
            if (testFile) evidence = demoteEvidence(evidence);

            const trace: TraceStep[] = [
              {
                kind: "source",
                file: relFile,
                line: getNodeLine(serialized),
                note: `full object \`${whole.label}\` serialized with JSON.stringify`,
              },
              {
                kind: "sink",
                file: relFile,
                line: getNodeLine(call),
                note: `${sink.callText} (${sink.provider})`,
              },
            ];

            findings.push({
              rule_id: "AI004",
              title: "Sensitive data sent to LLM",
              severity: "high",
              file: relFile,
              line: getNodeLine(candidate),
              summary: `Entire \`${whole.label}\` object is serialized into an LLM prompt.`,
              description:
                `JSON.stringify(${whole.label}) sends every field of the object — potentially passwords, tokens, internal IDs, and PII — to the ${sink.provider} API. Whole-object serialization leaks fields you never intended to share.`,
              recommendation:
                "Pick only the fields the model needs (e.g. { name: user.name, plan: user.plan }) and redact identifiers. Never serialize full ORM/session objects.",
              confidence: evidenceConfidence(evidence),
              evidence,
              trace,
            });
          }
        }
      }
    }

    return findings;
  },
};
