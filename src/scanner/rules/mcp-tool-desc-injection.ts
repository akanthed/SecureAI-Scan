import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getCallsWithin, getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";
import type { Evidence } from "../types.js";
import { isLikelyLlmCall, getObjectProperty } from "./llm-rule-utils.js";

// MCP / tool-registry listing call patterns
const MCP_LISTING_METHODS = [
  "listtools",
  "list_tools",
  "gettools",
  "get_tools",
  "discovertools",
  "discover_tools",
  "fetchtoollist",
  "fetch_tool_list",
  "loadtools",
  "load_tools",
  "gettoolmanifest",
  "get_tool_manifest",
  "getregisteredtools",
  "get_registered_tools",
];

function isMcpToolListingCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const text = node.getExpression().getText().toLowerCase();
  return MCP_LISTING_METHODS.some((m) => text.endsWith(m));
}

// Collect variables assigned from MCP tool listing calls within a function scope.
// Only propagates taint through direct identifier assignment, not through method
// chains (so tools.filter(validate) breaks the taint, acting as trust-demotion).
function collectToolListVars(fnNode: Node): Set<string> {
  const tainted = new Set<string>();

  for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const init = decl.getInitializer();
    if (!init) continue;

    let expr: Node = init;
    if (Node.isAwaitExpression(expr)) {
      expr = expr.getExpression();
    }

    if (Node.isCallExpression(expr) && isMcpToolListingCall(expr)) {
      tainted.add(decl.getName());
      continue;
    }

    // Propagate only through bare identifier copies, not method calls.
    // If someone writes `const safe = tools.filter(validateDesc)`, that breaks taint.
    if (Node.isIdentifier(init) && tainted.has(init.getText())) {
      tainted.add(decl.getName());
    }
  }

  return tainted;
}

// Returns the system/developer message content node if any tainted variable
// reaches it, otherwise undefined.
function toolVarReachesSystemPrompt(fnNode: Node, tainted: Set<string>): Node | undefined {
  for (const call of getCallsWithin(fnNode)) {
    if (!isLikelyLlmCall(call)) continue;

    const firstArg = call.getArguments()[0];
    if (!firstArg) continue;

    // Pattern: { messages: [{ role: 'system', content: `...${tools}...` }] }
    if (Node.isObjectLiteralExpression(firstArg)) {
      const messages = getObjectProperty(firstArg, "messages");
      if (messages && Node.isArrayLiteralExpression(messages)) {
        for (const element of messages.getElements()) {
          if (!Node.isObjectLiteralExpression(element)) continue;
          const role = getObjectProperty(element, "role")
            ?.getText()
            .replace(/['"]/g, "")
            .toLowerCase();
          if (role !== "system" && role !== "developer") continue;

          const content = getObjectProperty(element, "content");
          if (!content) continue;
          if ([...tainted].some((v) => content.getText().includes(v))) return content;
        }
      }

      // Anthropic-style { system: `...${tools}...` }
      for (const key of ["system", "systemPrompt", "system_prompt"]) {
        const prop = getObjectProperty(firstArg, key);
        if (prop && [...tainted].some((v) => prop.getText().includes(v))) return prop;
      }
    }
  }
  return undefined;
}

export const ruleMcpToolDescInjection: Rule = {
  id: "MCP001",
  title: "MCP tool metadata reaches system prompt without trust-demotion",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      if (isTestFilePath(relPath)) continue;

      for (const fnNode of getFileFunctions(sourceFile)) {
        const tainted = collectToolListVars(fnNode);
        if (tainted.size === 0) continue;

        const sinkNode = toolVarReachesSystemPrompt(fnNode, tainted);
        if (!sinkNode) continue;

        const hasTrustDemotion = hasSanitizationNearby(fnNode.getText());
        // Taint from listTools() to a system prompt is a traced dataflow.
        const evidence: Evidence = hasTrustDemotion ? demoteEvidence("proven") : "proven";

        findings.push({
          rule_id: "MCP001",
          title: "MCP tool metadata reaches system prompt without trust-demotion",
          severity: "critical",
          file: relPath,
          line: getNodeLine(sinkNode),
          summary:
            "Tool metadata returned by an MCP listing call flows into a system/developer prompt without validation.",
          description:
            "Tool descriptions and names arrive from the MCP server at connect time — they are not in the codebase being scanned. A compromised or malicious third-party server can embed override instructions in a tool description. When that metadata is interpolated directly into a system prompt, the injected instructions execute in a privileged context. This is the same threat model as RAG poisoning (VEC003): untrusted external text reaching an instruction sink. A phrase-list scan of the client codebase cannot detect this because the payload travels over the wire, not through source.",
          recommendation:
            "Treat MCP tool metadata as untrusted input. Validate name and description fields against an allowlist schema before use. Prefer placing tool metadata in user/data-role messages rather than the system prompt. If system-level injection is necessary, apply a sanitizer that strips instruction-like patterns. For third-party servers, pin to a known-good version and verify server integrity.",
          confidence: evidenceConfidence(evidence),
          evidence,
          trace: [
            {
              kind: "source",
              file: relPath,
              line: getNodeLine(sinkNode),
              note: "tool metadata from MCP listing call (arrives over the wire at connect time)",
            },
            {
              kind: "sink",
              file: relPath,
              line: getNodeLine(sinkNode),
              note: "interpolated into system/developer prompt",
            },
          ],
        });
      }
    }

    return findings;
  },
};
