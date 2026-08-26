import { Node, type CallExpression, type SourceFile } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence } from "../confidence.js";
import { getObjectProperty, getStringValue } from "./llm-rule-utils.js";
import {
  findCrossToolReference,
  findInvisibleUnicode,
  matchInjectionPhrases,
} from "../tool-poisoning-checks.js";

/**
 * MCP007–MCP009: tool poisoning via tool metadata.
 *
 * Tool names and descriptions enter the agent's context as trusted content.
 * These rules statically inspect every tool registration in MCP server code
 * (@modelcontextprotocol/sdk `server.tool` / `server.registerTool`, fastmcp
 * `server.addTool`) for the three known poisoning shapes: invisible Unicode,
 * agent-directed injection phrases, and cross-tool shadowing.
 */

const MCP_SERVER_MODULES = [
  (s: string) => s === "@modelcontextprotocol/sdk" || s.startsWith("@modelcontextprotocol/sdk/"),
  (s: string) => s === "fastmcp",
];

export const TOOL_METHODS = new Set(["tool", "registertool", "addtool"]);

function isMcpServerModule(spec: string): boolean {
  return MCP_SERVER_MODULES.some((test) => test(spec));
}

export function fileImportsMcpServerSdk(sourceFile: SourceFile): boolean {
  for (const imp of sourceFile.getImportDeclarations()) {
    if (isMcpServerModule(imp.getModuleSpecifierValue())) return true;
  }
  const requireMatches = sourceFile.getFullText().matchAll(/require\(\s*["']([^"']+)["']\s*\)/g);
  for (const m of requireMatches) {
    if (isMcpServerModule(m[1])) return true;
  }
  return false;
}

interface ToolDefinition {
  name: string;
  /** name and every descriptive string found on the registration. */
  texts: Array<{ label: "name" | "description" | "title"; value: string; node: Node }>;
  call: CallExpression;
}

function extractToolDefinition(call: CallExpression): ToolDefinition | undefined {
  const exprText = call.getExpression().getText();
  const method = (exprText.split(".").pop() ?? "").toLowerCase();
  if (!TOOL_METHODS.has(method)) return undefined;

  const args = call.getArguments();
  if (args.length === 0) return undefined;

  const texts: ToolDefinition["texts"] = [];
  let name: string | undefined;

  // server.tool("name", "description", schema, handler) — positional strings.
  const firstString = getStringValue(args[0]);
  if (firstString !== undefined) {
    name = firstString;
    texts.push({ label: "name", value: firstString, node: args[0] });
    const secondString = args[1] ? getStringValue(args[1]) : undefined;
    if (secondString !== undefined) {
      texts.push({ label: "description", value: secondString, node: args[1] });
    }
  }

  // registerTool("name", { description, title }, handler) and
  // addTool({ name, description }) — object-carried metadata.
  for (const arg of args.slice(0, 2)) {
    if (!Node.isObjectLiteralExpression(arg)) continue;
    const nameProp = getObjectProperty(arg, "name");
    const nameValue = nameProp ? getStringValue(nameProp) : undefined;
    if (nameValue !== undefined) {
      name = name ?? nameValue;
      texts.push({ label: "name", value: nameValue, node: nameProp! });
    }
    for (const key of ["description", "title"] as const) {
      const prop = getObjectProperty(arg, key);
      const value = prop ? getStringValue(prop) : undefined;
      if (value !== undefined) texts.push({ label: key, value, node: prop! });
    }
  }

  if (!name || texts.length === 0) return undefined;
  return { name, texts, call };
}

function collectToolDefinitions(sourceFile: SourceFile): ToolDefinition[] {
  const defs: ToolDefinition[] = [];
  sourceFile.forEachDescendant((node) => {
    if (!Node.isCallExpression(node)) return;
    const def = extractToolDefinition(node);
    if (def) defs.push(def);
  });
  return defs;
}

interface CollectedTools {
  perFile: Array<{ file: string; defs: ToolDefinition[] }>;
  allToolNames: Set<string>;
}

// The three rules share one collection pass over the project; the scan
// pipeline hands every rule the same RuleContext object, so it keys the cache.
const collectionCache = new WeakMap<RuleContext, CollectedTools>();

function collectProjectTools(context: RuleContext): CollectedTools {
  const cached = collectionCache.get(context);
  if (cached) return cached;

  const perFile: CollectedTools["perFile"] = [];
  const allToolNames = new Set<string>();
  for (const sourceFile of context.sourceFiles) {
    if (!fileImportsMcpServerSdk(sourceFile)) continue;
    const defs = collectToolDefinitions(sourceFile);
    if (defs.length === 0) continue;
    perFile.push({ file: getRelativeFilePath(context.rootPath, sourceFile), defs });
    for (const def of defs) allToolNames.add(def.name);
  }

  const result = { perFile, allToolNames };
  collectionCache.set(context, result);
  return result;
}

export const ruleMcpInvisibleUnicode: Rule = {
  id: "MCP007",
  title: "Invisible Unicode in MCP tool metadata",
  severity: "critical",

  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const { file, defs } of collectProjectTools(context).perFile) {
      for (const def of defs) {
        for (const text of def.texts) {
          const invisible = findInvisibleUnicode(text.value);
          if (!invisible) continue;
          findings.push({
            rule_id: "MCP007",
            title: "Invisible Unicode in MCP tool metadata",
            severity: "critical",
            file,
            line: getNodeLine(text.node),
            summary: `Tool "${def.name}" ${text.label} contains ${invisible.codePoint} (${invisible.label}) at index ${invisible.index}.`,
            description:
              "Invisible or bidirectional Unicode in tool metadata hides content from human reviewers while the model still reads it — the canonical tool-poisoning delivery mechanism. There is no legitimate reason for these characters in a tool name or description.",
            recommendation:
              "Remove the invisible characters and audit how they were introduced; treat the tool definition as compromised until reviewed.",
            confidence: evidenceConfidence("proven"),
            evidence: "proven",
          });
        }
      }
    }
    return findings;
  },
};

export const ruleMcpInjectionPhrases: Rule = {
  id: "MCP008",
  title: "Injection phrasing in MCP tool description",
  severity: "high",

  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    for (const { file, defs } of collectProjectTools(context).perFile) {
      for (const def of defs) {
        for (const text of def.texts) {
          const phrases = matchInjectionPhrases(text.value);
          if (phrases.strong.length > 0) {
            findings.push({
              rule_id: "MCP008",
              title: "Injection phrasing in MCP tool description",
              severity: "high",
              file,
              line: getNodeLine(text.node),
              summary: `Tool "${def.name}" ${text.label} contains ${phrases.strong[0]}.`,
              description:
                "The description contains instructions aimed at the agent rather than documentation for the user — the pattern used by real-world tool-poisoning attacks (WhatsApp MCP rug-pull, postmark-mcp). Descriptions enter the model's context as trusted content.",
              recommendation:
                "Rewrite the description as plain documentation. If this text was not written by your team, treat the package as compromised.",
              confidence: evidenceConfidence("likely"),
              evidence: "likely",
            });
          } else if (phrases.weak.length >= 2) {
            findings.push({
              rule_id: "MCP008",
              title: "Injection phrasing in MCP tool description",
              severity: "medium",
              file,
              line: getNodeLine(text.node),
              summary: `Tool "${def.name}" ${text.label} combines ${phrases.weak.length} agent-directive phrases (${phrases.weak.join("; ")}).`,
              description:
                "Multiple agent-directed phrases in one description suggest it is steering the model's behavior rather than documenting the tool.",
              recommendation:
                "Review whether these directives belong in tool metadata; move behavioral policy into your own system prompt.",
              confidence: evidenceConfidence("heuristic"),
              evidence: "heuristic",
            });
          }
        }
      }
    }
    return findings;
  },
};

export const ruleMcpCrossToolShadowing: Rule = {
  id: "MCP009",
  title: "MCP tool description steers another tool",
  severity: "medium",

  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const { perFile, allToolNames } = collectProjectTools(context);
    for (const { file, defs } of perFile) {
      for (const def of defs) {
        for (const text of def.texts) {
          const crossTool = findCrossToolReference(text.value, def.name, allToolNames);
          if (!crossTool) continue;
          findings.push({
            rule_id: "MCP009",
            title: "MCP tool description steers another tool",
            severity: "medium",
            file,
            line: getNodeLine(text.node),
            summary: `Tool "${def.name}" ${text.label} directs behavior around tool "${crossTool.referencedTool}" ("${crossTool.directive.trim()}…").`,
            description:
              "A tool description that dictates when or how a different tool is used is the tool-shadowing attack: a malicious server manipulates calls that flow to legitimate tools it does not own.",
            recommendation:
              "Tool descriptions should document only their own tool. Cross-tool orchestration belongs in your agent's own policy, not in server-supplied metadata.",
            confidence: evidenceConfidence("likely"),
            evidence: "likely",
          });
        }
      }
    }
    return findings;
  },
};
