import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getCallsWithin, getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { isLikelyLlmCall } from "./llm-rule-utils.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";
import type { Evidence } from "../types.js";

// HTTP client functions callable bare: fetch(url), got(url), ky(url), request(url, cb).
const BARE_FETCH_NAMES = new Set(["fetch", "got", "ky", "request"]);

// HTTP client method calls: base object -> allowed method names. A Map, not
// a plain object — a base identifier literally named `constructor`,
// `toString`, etc. (seen in minified bundled JS) resolves to an
// Object.prototype value on a plain-object lookup instead of undefined.
const PROPERTY_FETCH_CALLS: Map<string, Set<string>> = new Map([
  ["axios", new Set(["get", "post", "put", "patch", "delete", "request"])],
  ["http", new Set(["get", "request"])],
  ["https", new Set(["get", "request"])],
  ["superagent", new Set(["get", "post", "put", "patch", "delete"])],
]);

// Response extraction — property/method names for content pulled off an
// HTTP response object.
const RESPONSE_CONTENT_PROPS = ["data", "body", "content", "result", "output", "message"];
const RESPONSE_CONTENT_METHODS = ["text", "json"];

function unwrapAwait(node: Node): Node {
  return Node.isAwaitExpression(node) ? node.getExpression() : node;
}

/**
 * True only for an actual call expression whose callee is a known HTTP
 * client function/method, matched by exact identifier/property name — not
 * a substring match against the callee's text. A substring check on
 * "request" previously matched `extra.sendRequest(...)` (an MCP
 * protocol call to the client, e.g. sampling/elicitation), because
 * "sendRequest" contains "request" as a substring.
 */
function isFetchLikeCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const expr = node.getExpression();
  if (Node.isIdentifier(expr)) {
    return BARE_FETCH_NAMES.has(expr.getText());
  }
  if (Node.isPropertyAccessExpression(expr)) {
    const baseText = expr.getExpression().getText().split(".").pop() ?? "";
    const allowedMethods = PROPERTY_FETCH_CALLS.get(baseText.toLowerCase());
    return allowedMethods?.has(expr.getName().toLowerCase()) ?? false;
  }
  return false;
}

/**
 * Exported for mcp-untrusted-tool-source.ts (MCP011), which needs the same
 * "resolved fetch call -> derived vars, multi-hop" derivation for MCP tool
 * handlers. Reusing this instead of a rule-local reimplementation is the
 * documented convention (see llm-rule-utils.ts's getPromptParts) — a
 * rule-specific rewrite of the same logic is exactly what caused the AI007
 * false-positive class.
 */
export function collectFetchDerivedIdentifiers(functionNode: Node): Set<string> {
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

      for (const fnNode of getFileFunctions(sourceFile)) {
        const fetchVars = collectFetchDerivedIdentifiers(fnNode);
        if (fetchVars.size === 0) continue;

        const calls = getCallsWithin(fnNode);
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
