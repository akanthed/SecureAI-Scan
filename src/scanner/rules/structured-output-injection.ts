import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getCallsWithin, getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { resolveLlmSink, isLikelyLlmCall } from "./llm-rule-utils.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";

/**
 * A schema-validated LLM call (generateObject/streamObject, or the same
 * "give it a schema, get a typed value back" shape from other structured-
 * output SDKs) only proves the *shape* of the result — that a field named
 * `command` is a string. It proves nothing about that string's content. A
 * schema still lets the model put anything into a `z.string()` field,
 * including a shell command or a prompt-injection payload.
 *
 * This is a different failure mode from AI012 (unvalidated-structured-
 * output.ts): AI012 flags output that was never schema-checked at all.
 * This rule flags output that WAS schema-checked and, precisely because of
 * that, gets treated as trusted downstream with no further content check —
 * the schema becomes a false sense of safety.
 */

// Structured-output call names: the API surface whose entire contract is
// "you give a schema, you get a typed, schema-conformant value back."
const STRUCTURED_OUTPUT_METHOD_NAMES = new Set(["generateobject", "streamobject"]);

// Sinks where a schema-validated-but-content-unchecked string is dangerous:
// shell/process execution, or splicing into a second LLM prompt.
const EXEC_SINK_NAMES = new Set(["exec", "execsync", "execfile", "execfilesync", "spawn", "spawnsync"]);

function isStructuredOutputCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const sink = resolveLlmSink(node);
  if (!sink) return false;
  const cleaned = sink.callText.split("(")[0];
  const method = (cleaned.split(".").pop() ?? "").replace(/[^A-Za-z]/g, "").toLowerCase();
  return STRUCTURED_OUTPUT_METHOD_NAMES.has(method);
}

interface StructuredOrigin {
  line: number;
  note: string;
}

/** Vars assigned from a structured-output call, propagated through property access to a fixed point. */
function collectStructuredOutputVars(fnNode: Node): Map<string, StructuredOrigin> {
  const vars = new Map<string, StructuredOrigin>();

  for (const call of getCallsWithin(fnNode)) {
    if (!isStructuredOutputCall(call)) continue;
    const parent = call.getParent();
    let declNode: Node | undefined;
    if (Node.isVariableDeclaration(parent)) {
      declNode = parent;
    } else if (Node.isAwaitExpression(parent)) {
      const grandParent = parent.getParent();
      if (Node.isVariableDeclaration(grandParent)) declNode = grandParent;
    }
    if (!declNode || !Node.isVariableDeclaration(declNode)) continue;

    // generateObject/streamObject are used destructured in practice:
    // const { object } = await generateObject(...). Bind every destructured
    // name (not just a plain `const result = ...`), since that's the shape
    // real usage actually takes.
    const nameNode = declNode.getNameNode();
    if (Node.isObjectBindingPattern(nameNode)) {
      for (const element of nameNode.getElements()) {
        const name = element.getName();
        vars.set(name, { line: getNodeLine(declNode), note: `schema-validated result \`${name}\`` });
      }
    } else {
      const name = declNode.getName();
      vars.set(name, { line: getNodeLine(declNode), note: `schema-validated result \`${name}\`` });
    }
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (const decl of fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      if (vars.has(decl.getName())) continue;
      const init = decl.getInitializer();
      if (!init) continue;
      const initText = init.getText();
      const parentKey = [...vars.keys()].find((v) => initText.startsWith(v + ".") || initText.startsWith(v + "["));
      if (parentKey) {
        vars.set(decl.getName(), vars.get(parentKey)!);
        changed = true;
      }
    }
  }

  return vars;
}

function isExecSinkCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  const expr = node.getExpression();
  const name = (Node.isPropertyAccessExpression(expr) ? expr.getName() : expr.getText())
    .replace(/[^A-Za-z]/g, "")
    .toLowerCase();
  return EXEC_SINK_NAMES.has(name);
}

export const ruleStructuredOutputInjection: Rule = {
  id: "AI013",
  title: "Schema-validated LLM output reused as trusted input without content sanitization",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relPath = getRelativeFilePath(context.rootPath, sourceFile);
      const isTest = isTestFilePath(relPath);

      for (const fnNode of getFileFunctions(sourceFile)) {
        const structuredVars = collectStructuredOutputVars(fnNode);
        if (structuredVars.size === 0) continue;

        for (const call of getCallsWithin(fnNode)) {
          const isExecSink = isExecSinkCall(call);
          const isPromptSink = !isExecSink && isLikelyLlmCall(call) && !isStructuredOutputCall(call);
          if (!isExecSink && !isPromptSink) continue;

          const args = call.getArguments();
          const matchedVar = [...structuredVars.keys()].find((v) =>
            args.some((a) => a.getText().includes(v)),
          );
          if (!matchedVar) continue;

          const origin = structuredVars.get(matchedVar)!;
          const sinkLine = getNodeLine(call);
          const enclosingFnText = fnNode.getText();
          if (hasSanitizationNearby(enclosingFnText)) continue;

          const sinkNote = isExecSink
            ? "shell/process execution using the schema-validated field"
            : "spliced into a second LLM prompt using the schema-validated field";

          const trace: TraceStep[] = [
            { kind: "source", file: relPath, line: origin.line, note: origin.note },
            { kind: "sink", file: relPath, line: sinkLine, note: sinkNote },
          ];

          findings.push({
            rule_id: "AI013",
            title: "Schema-validated LLM output reused as trusted input without content sanitization",
            severity: "high",
            file: relPath,
            line: sinkLine,
            summary: isExecSink
              ? "A field from a schema-validated LLM result is passed to a shell/process execution call."
              : "A field from a schema-validated LLM result is spliced into another LLM prompt.",
            description:
              "A structured-output call (generateObject/streamObject) proves the result matches its schema's shape — a field typed as a string is guaranteed to be a string. It proves nothing about that string's content: the model can still put a shell command, a prompt-injection payload, or any other attacker-influenced text into a schema-conformant field. Treating \"it passed the schema\" as \"it's safe to execute or re-prompt with\" carries the same risk as using unsanitized user input in that position.",
            recommendation:
              "Validate the field's content (not just its type) before using it as a command or prompt fragment — an allowlist of accepted values, a strict format check, or explicit escaping. Never let a schema's shape guarantee stand in for a content check.",
            confidence: evidenceConfidence(isTest ? demoteEvidence("likely") : "likely"),
            evidence: isTest ? demoteEvidence("likely") : "likely",
            trace,
          });
        }
      }
    }

    return findings;
  },
};
