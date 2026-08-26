import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getFileCalls, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
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

// "token" compounds that name metadata *about* tokens (a URL, a type, a
// lifetime) rather than a token value itself — e.g. OAuth discovery fields
// like `token_endpoint`/`tokenType`/`tokenUrl`. Logging these leaks nothing.
const NON_SECRET_TOKEN_SUFFIXES = new Set([
  "endpoint",
  "url",
  "uri",
  "type",
  "expiry",
  "expires",
  "ttl",
  "issuer",
  "length",
]);

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
    // Single tokens, skipping "token"/"secret" etc. when immediately
    // followed by a metadata suffix ("token_endpoint" describes a URL, not
    // a credential value).
    const candidates: string[] = [];
    for (let i = 0; i < tokens.length; i += 1) {
      if (
        (tokens[i] === "token" || tokens[i] === "secret") &&
        NON_SECRET_TOKEN_SUFFIXES.has(tokens[i + 1] ?? "")
      ) {
        continue;
      }
      candidates.push(tokens[i]);
    }
    // Adjacent-pair joins so API_KEY / apiKey / OPENAI_API_KEY all produce
    // "apikey".
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

      for (const call of getFileCalls(sourceFile)) {
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
        // Both kinds only matter in files that actually talk to an LLM — this
        // rule is LLM-secret-in-prompt-pipeline logging, not a general
        // secret-scanner (out of scope: see CLAUDE.md's precision contract).
        // Only the "prompt" branch was gated here; a stripe/agent-toolkit
        // benchmark demo app with zero LLM SDK imports fired on a
        // console.log of a bcrypt-hashed password in a React form handler —
        // exactly the general-purpose-secret-scanning false positive class
        // this scanner explicitly disclaims being.
        if (!llmFile) continue;

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
