import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";
import type { Evidence } from "../types.js";

// HTTP client patterns that fetch external content
const FETCH_PATTERNS = [
  "fetch(",
  "axios.get",
  "axios.post",
  "axios.request",
  "http.get",
  "https.get",
  "got(",
  "request(",
  "superagent",
  "ky(",
];

// Response extraction patterns — text/json content from HTTP responses
const RESPONSE_CONTENT_PATTERNS = [
  ".text()",
  ".json()",
  ".data",
  ".body",
  ".content",
  ".result",
  ".output",
  ".message",
];

function isFetchLikeCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const text = node.getExpression().getText().toLowerCase();
  return FETCH_PATTERNS.some((p) => text.includes(p.replace("(", "")));
}

function collectFetchDerivedIdentifiers(functionNode: Node): Set<string> {
  const derived = new Set<string>();

  for (const decl of functionNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init) continue;
    const initText = init.getText().toLowerCase();

    // Direct fetch call result
    const isFetchResult = FETCH_PATTERNS.some((p) => initText.includes(p.replace("(", "")));
    // Await of a fetch result
    const isAwaited =
      Node.isAwaitExpression(init) &&
      FETCH_PATTERNS.some((p) => init.getText().toLowerCase().includes(p.replace("(", "")));
    // Property access on a fetch-derived var
    const isDerivedFromFetch =
      Node.isPropertyAccessExpression(init) &&
      derived.has(init.getExpression().getText()) &&
      RESPONSE_CONTENT_PATTERNS.some((p) => initText.endsWith(p.replace("()", "").replace(".", "")));

    if (isFetchResult || isAwaited || isDerivedFromFetch) {
      derived.add(decl.getName());
    }

    // Also catch: const text = await response.text()
    if (
      Node.isAwaitExpression(init) &&
      Node.isCallExpression(init.getExpression())
    ) {
      const innerText = init.getExpression().getText().toLowerCase();
      if (
        RESPONSE_CONTENT_PATTERNS.some((p) => innerText.endsWith(p.replace("()", ""))) &&
        derived.size > 0
      ) {
        derived.add(decl.getName());
      }
    }
  }

  return derived;
}

export const ruleIndirectPromptInjection: Rule = {
  id: "AI010",
  title: "Indirect prompt injection via HTTP response",
  severity: "high",
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

        const fetchVars = collectFetchDerivedIdentifiers(fnNode);
        if (fetchVars.size === 0) continue;

        const calls = fnNode.getDescendantsOfKind(SyntaxKind.CallExpression);
        for (const call of calls) {
          if (!isLikelyLlmCall(call)) continue;

          const callText = call.getText();
          const fnText = fnNode.getText();
          const usesExternalContent = [...fetchVars].some((v) => callText.includes(v));
          if (!usesExternalContent) continue;

          const hasSanitization = hasSanitizationNearby(fnText);
          let evidence: Evidence = "likely";
          if (isTest || hasSanitization) evidence = demoteEvidence(evidence);

          findings.push({
            rule_id: "AI010",
            title: "Indirect prompt injection via HTTP response",
            severity: "high",
            file: relPath,
            line: getNodeLine(call),
            summary: "External HTTP response content flows into LLM prompt without sanitization.",
            description:
              "Content fetched from an external URL is passed to an LLM prompt. An attacker who controls the external resource can inject instructions that override your system prompt.",
            recommendation:
              "Treat all externally fetched content as untrusted. Use a separate user-role message, limit allowed content with a schema, and consider a content safety classifier before forwarding to the LLM.",
            confidence: evidenceConfidence(evidence),
            evidence,
          });
        }
      }
    }

    return findings;
  },
};
