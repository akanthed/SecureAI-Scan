import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import {
  evidenceConfidence,
  demoteEvidence,
  identifierTokens,
  isTestFilePath,
} from "../confidence.js";
import { fileImportsLlmSdk } from "./llm-rule-utils.js";

const LOGGER_CALLEES = new Set([
  "console.log",
  "console.info",
  "console.warn",
  "console.error",
  "console.debug",
  "logger.log",
  "logger.info",
  "logger.warn",
  "logger.error",
  "logger.debug",
  "log.info",
  "log.debug",
  "log.warn",
  "log.error",
]);

// Always-sensitive: secrets. Exact-token match, never substring.
const SECRET_TOKENS = new Set(["password", "passwd", "apikey", "secret", "token", "credentials"]);

// LLM-context-sensitive: only meaningful when the file actually talks to an LLM.
const PROMPT_TOKENS = new Set(["prompt", "prompts", "messages", "completion", "systemprompt"]);

function isLoggerCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const text = node.getExpression().getText();
  return LOGGER_CALLEES.has(text);
}

function classifyArg(arg: Node): "secret" | "prompt" | undefined {
  const names: string[] = [];
  if (Node.isIdentifier(arg)) names.push(arg.getText());
  for (const id of arg.getDescendantsOfKind(SyntaxKind.Identifier)) {
    names.push(id.getText());
  }
  for (const prop of arg.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression)) {
    names.push(prop.getName());
  }

  let promptHit = false;
  for (const name of names) {
    const tokens = identifierTokens(name);
    // Include adjacent-pair joins so API_KEY / apiKey / OPENAI_API_KEY all
    // produce "apikey".
    const candidates = [...tokens];
    for (let i = 0; i < tokens.length - 1; i += 1) {
      candidates.push(tokens[i] + tokens[i + 1]);
    }
    if (candidates.some((t) => SECRET_TOKENS.has(t))) {
      return "secret";
    }
    if (candidates.some((t) => PROMPT_TOKENS.has(t))) {
      promptHit = true;
    }
  }
  return promptHit ? "prompt" : undefined;
}

export const ruleSensitivePromptLogging: Rule = {
  id: "AI002",
  title: "Sensitive prompt or secret logged",
  severity: "medium",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);
      const llmFile = fileImportsLlmSdk(sourceFile);

      for (const call of sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression)) {
        if (!isLoggerCall(call)) continue;

        let kind: "secret" | "prompt" | undefined;
        for (const arg of call.getArguments()) {
          const argKind = classifyArg(arg);
          if (argKind === "secret") {
            kind = "secret";
            break;
          }
          if (argKind === "prompt") kind = "prompt";
        }
        if (!kind) continue;
        // "prompt"-named variables only matter in files that use an LLM SDK;
        // this is what keeps ordinary web-app logging out of the results.
        if (kind === "prompt" && !llmFile) continue;

        let evidence: Evidence = kind === "secret" ? "likely" : "likely";
        if (testFile) evidence = demoteEvidence(evidence);

        findings.push({
          rule_id: "AI002",
          title: kind === "secret" ? "Secret value logged" : "Prompt content logged",
          severity: kind === "secret" ? "high" : "medium",
          file: relFile,
          line: getNodeLine(call),
          summary:
            kind === "secret"
              ? "A variable named like a secret (password/apiKey/token) is written to logs."
              : "Prompt or message content is written to logs in a file that calls an LLM.",
          description:
            kind === "secret"
              ? "Secrets in log output persist in log storage, CI output, and observability tools, where far more people and systems can read them than the original code path."
              : "Prompts routinely contain user data and PII. Logging them copies that data into log pipelines with weaker access controls and longer retention than your database.",
          recommendation:
            kind === "secret"
              ? "Never log secret values. Log a redacted placeholder or the key's name only."
              : "Log a request ID instead of prompt content, or redact user-supplied fields before logging.",
          confidence: evidenceConfidence(evidence),
          evidence,
        });
      }
    }

    return findings;
  },
};
