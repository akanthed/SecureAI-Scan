import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getCallsWithin, getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { evidenceConfidence } from "../confidence.js";
import { isLikelyLlmCall, resolveLlmSink } from "./llm-rule-utils.js";

// Note: JSON.parse is intentionally NOT here — parsing structured output is
// normal and is covered by AI012 (unvalidated structured output) instead.
const DANGEROUS_CALLEES = [
  "eval",
  "exec",
  "execsync",
  "spawn",
  "spawnsync",
  "query",
  "raw",
];

interface OutputOrigin {
  line: number;
  note: string;
}

function collectLlmOutputIdentifiers(functionNode: Node): Map<string, OutputOrigin> {
  const outputs = new Map<string, OutputOrigin>();

  for (const declaration of functionNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
    const initializer = declaration.getInitializer();
    if (!initializer) {
      continue;
    }
    if (
      isLikelyLlmCall(initializer) ||
      initializer
        .getDescendantsOfKind(SyntaxKind.CallExpression)
        .some(isLikelyLlmCall)
    ) {
      const name = declaration.getName();
      outputs.set(name.toLowerCase(), {
        line: getNodeLine(declaration),
        note: `LLM response \`${name}\``,
      });
    }
  }

  // Propagate through derivations: const code = completion.choices[0].message.content
  // — the origin stays the earliest LLM-call assignment in the chain.
  let changed = true;
  let passes = 0;
  while (changed && passes < 4) {
    changed = false;
    passes += 1;
    for (const declaration of functionNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration)) {
      const name = declaration.getName().toLowerCase();
      if (outputs.has(name)) continue;
      const initializer = declaration.getInitializer();
      if (!initializer) continue;
      const derivedFrom = initializer
        .getDescendantsOfKind(SyntaxKind.Identifier)
        .find((id) => outputs.has(id.getText().toLowerCase()));
      const parentKey =
        Node.isIdentifier(initializer) && outputs.has(initializer.getText().toLowerCase())
          ? initializer.getText().toLowerCase()
          : derivedFrom?.getText().toLowerCase();
      if (parentKey) {
        outputs.set(name, outputs.get(parentKey)!);
        changed = true;
      }
    }
  }

  return outputs;
}

/** First LLM-output identifier referenced in a call's arguments, if any. */
function matchingLlmOutputArg(call: Node, llmOutputs: Map<string, OutputOrigin>): string | undefined {
  if (!Node.isCallExpression(call)) {
    return undefined;
  }
  for (const arg of call.getArguments()) {
    if (Node.isIdentifier(arg) && llmOutputs.has(arg.getText().toLowerCase())) {
      return arg.getText().toLowerCase();
    }
    const hit = arg
      .getDescendantsOfKind(SyntaxKind.Identifier)
      .find((identifier) => llmOutputs.has(identifier.getText().toLowerCase()));
    if (hit) return hit.getText().toLowerCase();
  }
  return undefined;
}

function isDangerousSink(call: Node): boolean {
  if (!Node.isCallExpression(call)) {
    return false;
  }
  const callee = call.getExpression().getText().toLowerCase();
  if (!DANGEROUS_CALLEES.some((dangerous) => callee === dangerous || callee.endsWith(`.${dangerous}`))) {
    return false;
  }
  // "query" name-matches a real SQL sink (db.query(sql), pool.query(...))
  // but is also a legitimate LLM/agent invocation verb (claudeSdk.query(...))
  // — found via a false positive on the Claude Agent SDK's own
  // claudeSdk.query() call, which shares the bare verb "query" with
  // GENERATION_METHODS in llm-rule-utils.ts. A call that is
  // import-resolved (or name-hinted) as an LLM invocation in its own right
  // cannot simultaneously be the dangerous sink receiving that LLM's output —
  // reusing the existing resolver here, rather than adding a second
  // independent name heuristic, keeps the exclusion consistent with how the
  // rest of the ruleset already decides what counts as "an LLM call".
  if (resolveLlmSink(call)) {
    return false;
  }
  return true;
}

/** LLM-output identifier assigned into .innerHTML/.outerHTML, if any. */
function innerHtmlLlmOutputMatch(node: Node, llmOutputs: Map<string, OutputOrigin>): string | undefined {
  if (!Node.isBinaryExpression(node)) {
    return undefined;
  }
  const left = node.getLeft().getText().toLowerCase();
  if (!left.endsWith(".innerhtml") && !left.endsWith(".outerhtml")) {
    return undefined;
  }
  return node
    .getRight()
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .find((identifier) => llmOutputs.has(identifier.getText().toLowerCase()))
    ?.getText()
    .toLowerCase();
}

export const ruleUnsafeOutputHandling: Rule = {
  id: "AI005",
  title: "Unsafe LLM output handling",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);

      for (const functionNode of getFileFunctions(sourceFile)) {
        const llmOutputs = collectLlmOutputIdentifiers(functionNode);
        if (llmOutputs.size === 0) {
          continue;
        }

        for (const call of getCallsWithin(functionNode)) {
          if (!isDangerousSink(call)) continue;
          const matched = matchingLlmOutputArg(call, llmOutputs);
          if (!matched) continue;
          const origin = llmOutputs.get(matched)!;
          const sinkLine = getNodeLine(call);

          const trace: TraceStep[] = [
            { kind: "source", file: relFile, line: origin.line, note: origin.note },
            {
              kind: "sink",
              file: relFile,
              line: sinkLine,
              note: `passed to \`${call.getExpression().getText()}\``,
            },
          ];

          findings.push({
            rule_id: "AI005",
            title: "Unsafe LLM output handling",
            severity: "critical",
            file: relFile,
            line: sinkLine,
            summary: "LLM output is passed to a dangerous sink.",
            description:
              "Model output flows into code execution, command execution, database, HTML, or parser behavior without an obvious validation boundary.",
            recommendation:
              "Validate model output against a strict schema and keep it away from eval, shell, SQL, HTML, and dynamic execution sinks.",
            confidence: evidenceConfidence("likely"),
            evidence: "likely",
            trace,
          });
        }

        for (const assignment of functionNode.getDescendantsOfKind(SyntaxKind.BinaryExpression)) {
          const matched = innerHtmlLlmOutputMatch(assignment, llmOutputs);
          if (!matched) continue;
          const origin = llmOutputs.get(matched)!;
          const sinkLine = getNodeLine(assignment);

          const trace: TraceStep[] = [
            { kind: "source", file: relFile, line: origin.line, note: origin.note },
            {
              kind: "sink",
              file: relFile,
              line: sinkLine,
              note: `assigned to \`${assignment.getLeft().getText()}\``,
            },
          ];

          findings.push({
            rule_id: "AI005",
            title: "Unsafe LLM output handling",
            severity: "critical",
            file: relFile,
            line: sinkLine,
            summary: "LLM output is assigned to HTML.",
            description:
              "Model output is rendered as HTML without an obvious sanitizer, which can turn prompt output into script execution.",
            recommendation:
              "Render model output as text or sanitize it with a proven HTML sanitizer before assigning it to DOM HTML sinks.",
            confidence: evidenceConfidence("likely"),
            evidence: "likely",
            trace,
          });
        }
      }
    }

    return findings;
  },
};

