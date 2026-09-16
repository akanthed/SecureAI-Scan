import { Node, SyntaxKind, type CallExpression, type SourceFile } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";
import { fileImportsMcpServerSdk, TOOL_METHODS } from "./mcp-tool-poisoning.js";
import { collectFetchDerivedIdentifiers } from "./indirect-prompt-injection.js";

/**
 * MCP011: an MCP tool handler fetches from an external/unauthenticated
 * source and returns the response as the tool result with no sanitization
 * in between.
 *
 * This is the Sentry-MCP-DSN attack shape (2026): the tool server itself is
 * the injection vector — whoever can write to the fetched endpoint gets to
 * plant instructions into whatever agent calls the tool, without touching
 * the tool's static name/description text at all (that's MCP007/MCP008,
 * which this rule does not duplicate).
 */

function findHandlerFunction(call: CallExpression): Node | undefined {
  const args = call.getArguments();
  const last = args[args.length - 1];
  if (last && (Node.isFunctionExpression(last) || Node.isArrowFunction(last))) return last;
  // registerTool("name", { ... }, handler) — handler may be the 3rd arg
  // when metadata is object-carried instead of positional.
  const secondToLast = args[args.length - 2];
  if (secondToLast && (Node.isFunctionExpression(secondToLast) || Node.isArrowFunction(secondToLast))) {
    return secondToLast;
  }
  return undefined;
}

function collectToolHandlers(sourceFile: SourceFile): Node[] {
  const handlers: Node[] = [];
  sourceFile.forEachDescendant((node) => {
    if (!Node.isCallExpression(node)) return;
    const method = (node.getExpression().getText().split(".").pop() ?? "").toLowerCase();
    if (!TOOL_METHODS.has(method)) return;
    const handler = findHandlerFunction(node);
    if (handler) handlers.push(handler);
  });
  return handlers;
}

export const ruleMcpUntrustedToolSource: Rule = {
  id: "MCP011",
  title: "External data returned as MCP tool result without validation",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      if (!fileImportsMcpServerSdk(sourceFile)) continue;
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const handler of collectToolHandlers(sourceFile)) {
        const fetchVars = collectFetchDerivedIdentifiers(handler);
        if (fetchVars.size === 0) continue;

        const handlerText = handler.getText();
        const hasSanitization = hasSanitizationNearby(handlerText);

        for (const returnStmt of handler.getDescendantsOfKind(SyntaxKind.ReturnStatement)) {
          const returnText = returnStmt.getText();
          const usesExternalContent = [...fetchVars].some((v) => returnText.includes(v));
          if (!usesExternalContent) continue;

          let evidence: Evidence = "likely";
          if (isTest || hasSanitization) evidence = demoteEvidence(evidence);

          findings.push({
            rule_id: "MCP011",
            title: "External data returned as MCP tool result without validation",
            severity: "high",
            file: relPath,
            line: getNodeLine(returnStmt),
            summary: "MCP tool handler returns externally fetched content as the tool result without sanitization.",
            description:
              "The tool handler fetches from an external source and returns the response body directly as the tool result. Whoever controls that source (a public webhook, an unauthenticated ingest endpoint, an error-tracking DSN) can inject instructions that the calling agent treats as trusted tool output.",
            recommendation:
              "Validate and sanitize external response content before returning it as a tool result. Restrict the shape of what the tool can return with a schema, and treat the fetched endpoint as untrusted input.",
            confidence: evidenceConfidence(evidence),
            evidence,
          });
        }
      }
    }

    return findings;
  },
};
