import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { calculateConfidence } from "../confidence.js";

const LOGGER_CALLEE_PATTERNS = [
  "console.log",
  "console.info",
  "console.warn",
  "console.error",
  "logger.log",
  "logger.info",
  "logger.warn",
  "logger.error",
  "logger.debug",
];

const SENSITIVE_NAMES = ["email", "token", "password", "apikey", "api_key"];
const PROMPT_NAMES = ["prompt", "messages", "completion", "response", "output"];

function isLoggerCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const text = node.getExpression().getText().toLowerCase();
  return LOGGER_CALLEE_PATTERNS.some((pattern) => text.includes(pattern));
}

function isSensitiveIdentifier(name: string): boolean {
  const normalized = name.toLowerCase();
  return (
    SENSITIVE_NAMES.some((s) => normalized.includes(s)) ||
    PROMPT_NAMES.some((p) => normalized.includes(p))
  );
}

function argumentContainsSensitiveData(arg: Node): boolean {
  const identifiers = arg.getDescendantsOfKind(SyntaxKind.Identifier);
  for (const id of identifiers) {
    if (isSensitiveIdentifier(id.getText())) {
      return true;
    }
  }

  const properties = arg.getDescendantsOfKind(
    SyntaxKind.PropertyAccessExpression,
  );
  for (const prop of properties) {
    if (isSensitiveIdentifier(prop.getName())) {
      return true;
    }
  }

  const text = arg.getText().toLowerCase();
  return (
    SENSITIVE_NAMES.some((name) => text.includes(name)) ||
    PROMPT_NAMES.some((name) => text.includes(name))
  );
}

export const ruleSensitivePromptLogging: Rule = {
  id: "AI002",
  title: "Sensitive prompt logging",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const calls = sourceFile.getDescendantsOfKind(
        SyntaxKind.CallExpression,
      );

      for (const call of calls) {
        if (!isLoggerCall(call)) {
          continue;
        }

        const args = call.getArguments();
        if (args.length === 0) {
          continue;
        }

        const hasSensitive = args.some(argumentContainsSensitiveData);
        if (!hasSensitive) {
          continue;
        }

        findings.push({
          rule_id: "AI002",
          title: "Sensitive prompt logging",
          severity: "high",
          file: getRelativeFilePath(context.rootPath, sourceFile),
          line: getNodeLine(call),
          summary: "Prompt or response data is logged.",
          description:
            "Prompt content or LLM responses are logged alongside potentially sensitive fields.",
          recommendation:
            "Avoid logging prompt/response data or redact sensitive fields like email, token, password, or apiKey.",
          confidence: calculateConfidence({
            directUserInput: true,
            stringConcatOrTemplate: false,
            requestObjectSource: false,
            confirmedLlmCall: false,
          }),
        });
      }
    }

    return findings;
  },
};
