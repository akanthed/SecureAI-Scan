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

// Response extraction — property/method names for content pulled off an
// HTTP response object.
const RESPONSE_CONTENT_PROPS = ["data", "body", "content", "result", "output", "message"];
const RESPONSE_CONTENT_METHODS = ["text", "json"];

function unwrapAwait(node: Node): Node {
  return Node.isAwaitExpression(node) ? node.getExpression() : node;
}

/**
 * True only for an actual call expression whose callee is a known HTTP
 * client function/method — not a substring match against arbitrary
 * initializer text (which previously matched things like `{ fetch: true }`
 * or a var named `prefetchedIds`).
 */
function isFetchLikeCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const text = node.getExpression().getText().toLowerCase();
  return FETCH_PATTERNS.some((p) => text.includes(p.replace("(", "")));
}

function collectFetchDerivedIdentifiers(functionNode: Node): Set<string> {
  const derived = new Set<string>();

  // Iterate to a fixed point so multi-hop chains (page = await fetch(url);
  // text = await page.text(); body = text.slice(...)) all get captured.
  let changed = true;
  while (changed) {
    changed = false;
    for (const decl of functionNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      if (derived.has(decl.getName())) continue;
      const init = decl.getInitializer();
      if (!init) continue;
      const unwrapped = unwrapAwait(init);

      // const page = fetch(url) / const page = await fetch(url)
      if (isFetchLikeCall(unwrapped)) {
        derived.add(decl.getName());
        changed = true;
        continue;
      }

      // const text = await response.text() / const json = response.json()
      if (Node.isCallExpression(unwrapped) && Node.isPropertyAccessExpression(unwrapped.getExpression())) {
        const callee = unwrapped.getExpression() as import("ts-morph").PropertyAccessExpression;
        const base = callee.getExpression();
        const method = callee.getName().toLowerCase();
        if (derived.has(base.getText()) && RESPONSE_CONTENT_METHODS.includes(method)) {
          derived.add(decl.getName());
          changed = true;
          continue;
        }
      }

      // const data = response.data / axiosRes.body
      if (Node.isPropertyAccessExpression(unwrapped)) {
        const base = unwrapped.getExpression();
        const prop = unwrapped.getName().toLowerCase();
        if (derived.has(base.getText()) && RESPONSE_CONTENT_PROPS.includes(prop)) {
          derived.add(decl.getName());
          changed = true;
        }
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
