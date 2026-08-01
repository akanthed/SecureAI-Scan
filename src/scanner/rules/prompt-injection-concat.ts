import { Node, SyntaxKind, type SourceFile } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext, TraceStep } from "../types.js";
import { getNodeLine, getRelativeFilePath, isStringConcatenation } from "../../utils/ast.js";
import { evidenceConfidence, demoteEvidence, isTestFilePath, hasSanitizationNearby } from "../confidence.js";
import { getPromptParts, resolveLlmSink, resolveLocalCallTarget } from "./llm-rule-utils.js";

// Interprocedural walk: at most this many function-call boundaries crossed
// between the tainted source and the LLM sink. Stricter than the depth>5
// guard on import-alias unwrapping elsewhere in this codebase — each hop
// here means trusting an entire second function's behavior based on static
// shape alone, a materially riskier bet than unwrapping a variable alias.
const MAX_INTERPROCEDURAL_HOPS = 2;

interface TaintInfo {
  /** identifier name → how it became tainted */
  tainted: Map<string, { origin: string; line: number; viaTemplate: boolean }>;
}

function isRequestObjectAccess(node: Node): boolean {
  if (!Node.isPropertyAccessExpression(node) && !Node.isElementAccessExpression(node)) {
    return false;
  }
  let root: Node = node;
  while (Node.isPropertyAccessExpression(root) || Node.isElementAccessExpression(root)) {
    root = root.getExpression();
  }
  if (!Node.isIdentifier(root)) return false;
  const rootName = root.getText().toLowerCase();
  if (rootName === "req" || rootName === "request") return true;
  if (rootName === "ctx") return node.getText().toLowerCase().startsWith("ctx.request");
  return false;
}

function isFunctionLike(node: Node): boolean {
  return (
    Node.isFunctionDeclaration(node) ||
    Node.isFunctionExpression(node) ||
    Node.isArrowFunction(node) ||
    Node.isMethodDeclaration(node)
  );
}

/**
 * Collect tainted identifiers in a function scope, propagating through
 * variable declarations whose initializer references a tainted identifier
 * (template literals, concatenation, direct copies). Iterates to fixpoint.
 *
 * `seed`, when provided, taints a specific parameter with an origin carried
 * in from a caller — this is how the interprocedural walk (below) continues
 * tracing a request-derived value across a function-call boundary without
 * duplicating any of this propagation logic.
 */
function collectTaint(
  fnNode: Node,
  seed?: { paramName: string; origin: string; line: number },
): TaintInfo {
  const tainted = new Map<string, { origin: string; line: number; viaTemplate: boolean }>();

  if (seed) {
    tainted.set(seed.paramName, { origin: seed.origin, line: seed.line, viaTemplate: false });
  }

  if (isFunctionLike(fnNode)) {
    const fn = fnNode as import("ts-morph").FunctionDeclaration;
    for (const param of fn.getParameters()) {
      const nameNode = param.getNameNode();
      if (Node.isIdentifier(nameNode)) {
        const name = nameNode.getText();
        const isRequestParam = ["req", "request", "ctx"].includes(name.toLowerCase());
        tainted.set(name, {
          origin: isRequestParam
            ? `request data \`${name}\``
            : `function parameter \`${name}\``,
          line: getNodeLine(param),
          viaTemplate: false,
        });
      }
      // Destructured params: ({ body }) or ({ input })
      if (Node.isObjectBindingPattern(nameNode)) {
        for (const element of nameNode.getElements()) {
          const bound = element.getNameNode();
          if (Node.isIdentifier(bound)) {
            tainted.set(bound.getText(), {
              origin: `destructured parameter \`${bound.getText()}\``,
              line: getNodeLine(element),
              viaTemplate: false,
            });
          }
        }
      }
    }
  }

  const decls = fnNode.getDescendantsOfKind(SyntaxKind.VariableDeclaration);
  let changed = true;
  let passes = 0;
  while (changed && passes < 5) {
    changed = false;
    passes += 1;
    for (const decl of decls) {
      const name = decl.getName();
      if (tainted.has(name)) continue;
      const init = decl.getInitializer();
      if (!init) continue;

      if (isRequestObjectAccess(init)) {
        tainted.set(name, {
          origin: `request data \`${init.getText()}\``,
          line: getNodeLine(decl),
          viaTemplate: false,
        });
        changed = true;
        continue;
      }

      const viaTemplate =
        Node.isTemplateExpression(init) || isStringConcatenation(init);
      if (viaTemplate) {
        // Template directly interpolating request data: strongest origin.
        const reqAccess = init.getDescendants().find(isRequestObjectAccess);
        if (reqAccess) {
          tainted.set(name, {
            origin: `request data \`${reqAccess.getText()}\``,
            line: getNodeLine(decl),
            viaTemplate: true,
          });
          changed = true;
          continue;
        }
      }
      if (viaTemplate || Node.isIdentifier(init)) {
        const ids = Node.isIdentifier(init)
          ? [init]
          : init.getDescendantsOfKind(SyntaxKind.Identifier);
        const hit = ids.find((id) => tainted.has(id.getText()));
        if (hit) {
          const parent = tainted.get(hit.getText())!;
          tainted.set(name, {
            origin: parent.origin,
            line: getNodeLine(decl),
            viaTemplate: true,
          });
          changed = true;
        }
      }
    }
  }

  return { tainted };
}

/** Find the tainted identifier (if any) referenced inside a prompt node. */
function findTaintedRef(
  node: Node,
  taint: TaintInfo,
): { name: string; origin: string; originLine: number } | undefined {
  // Direct request access inside the prompt expression itself
  for (const access of [node, ...node.getDescendants()]) {
    if (isRequestObjectAccess(access)) {
      return {
        name: access.getText(),
        origin: `request data \`${access.getText()}\``,
        originLine: getNodeLine(access),
      };
    }
  }
  const ids = Node.isIdentifier(node) ? [node] : node.getDescendantsOfKind(SyntaxKind.Identifier);
  for (const id of ids) {
    const info = taint.tainted.get(id.getText());
    if (info) return { name: id.getText(), origin: info.origin, originLine: info.line };
  }
  return undefined;
}

/** Does the prompt node dynamically compose strings (template/concat) or resolve to a var that does? */
function isDynamicComposition(node: Node, taint: TaintInfo): boolean {
  if (Node.isTemplateExpression(node) || isStringConcatenation(node)) return true;
  if (Node.isIdentifier(node)) {
    const info = taint.tainted.get(node.getText());
    return info?.viaTemplate ?? false;
  }
  return node
    .getDescendantsOfKind(SyntaxKind.TemplateExpression)
    .length > 0;
}

/** First tainted argument (and its position) passed into a call, if any. */
function findTaintedArgIndex(
  call: Node,
  taint: TaintInfo,
): { index: number; ref: { name: string; origin: string; originLine: number } } | undefined {
  if (!Node.isCallExpression(call)) return undefined;
  const args = call.getArguments();
  for (let i = 0; i < args.length; i += 1) {
    const ref = findTaintedRef(args[i], taint);
    if (ref) return { index: i, ref };
  }
  return undefined;
}

/**
 * Continues a prompt-injection trace inside a locally-resolved callee
 * function, reusing the exact same single-function detection logic
 * (`isDynamicComposition` / `findTaintedRef` / `resolveLlmSink` /
 * `getPromptParts`) as the base case in `run()` below — this function only
 * adds the recursion, trace accumulation, and evidence capping around it.
 */
function traceInterproceduralSink(
  fnNode: Node,
  taint: TaintInfo,
  relFile: string,
  precedingSteps: TraceStep[],
  rootOrigin: string,
  crossedTestFile: boolean,
  hopsRemaining: number,
  visited: Set<Node>,
  projectFiles: Set<SourceFile>,
  rootPath: string,
  findings: Finding[],
): void {
  for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const sink = resolveLlmSink(call);

    if (sink) {
      for (const part of getPromptParts(call)) {
        if (part.role === "user" || part.role === "assistant" || part.role === "tool") continue;
        if (!isDynamicComposition(part.node, taint)) continue;
        const taintedRef = findTaintedRef(part.node, taint);
        if (!taintedRef) continue;

        const isSystemRole = part.role === "system" || part.role === "developer";
        const sinkLine = getNodeLine(part.node);

        // Interprocedural findings are capped at "likely" even when the sink
        // is import-resolved: the dataflow crossed a function boundary that
        // was trusted based on static shape (parameter binding + no visible
        // sanitization), not fully verified the way a single-function trace
        // is. Never "proven" — see the plan's precision-risk rationale.
        let evidence: Evidence = "likely";
        if (crossedTestFile) evidence = demoteEvidence(evidence);
        if (!rootOrigin.startsWith("request data")) evidence = demoteEvidence(evidence);

        const trace: TraceStep[] = [...precedingSteps];
        if (taintedRef.name !== taintedRef.origin && !Node.isIdentifier(part.node)) {
          trace.push({
            kind: "flow",
            file: relFile,
            line: sinkLine,
            note: `interpolated via \`${taintedRef.name}\``,
          });
        } else if (Node.isIdentifier(part.node)) {
          trace.push({
            kind: "flow",
            file: relFile,
            line: sinkLine,
            note: `passed as \`${part.node.getText()}\``,
          });
        }
        trace.push({
          kind: "sink",
          file: relFile,
          line: getNodeLine(call),
          note: `${sink.callText} — ${isSystemRole ? `${part.role} role` : `${part.role} field`} (${sink.provider})`,
        });

        findings.push({
          rule_id: "AI001",
          title: "Prompt injection via user input",
          severity: isSystemRole ? "high" : "medium",
          file: relFile,
          line: sinkLine,
          summary: isSystemRole
            ? `User-controlled data reaches a ${part.role}-role prompt through a helper function call.`
            : "User-controlled data is mixed into the prompt string through a helper function call.",
          description: isSystemRole
            ? `Data originating from ${rootOrigin} flows through one or more function calls into the ${part.role} prompt of a ${sink.provider} call. Anything a user types becomes privileged instructions: "ignore previous instructions" attacks work directly.`
            : `Data originating from ${rootOrigin} flows through one or more function calls into the prompt string of a ${sink.provider} call, mixing untrusted text with instructions in the same trust context.`,
          recommendation:
            "Keep system/developer prompts static. Pass user input as a separate user-role message, and validate/sanitize any value a helper function forwards into a prompt.",
          confidence: evidenceConfidence(evidence),
          evidence,
          trace,
        });
      }
      continue;
    }

    if (hopsRemaining <= 0) continue;

    const argMatch = findTaintedArgIndex(call, taint);
    if (!argMatch) continue;

    const target = resolveLocalCallTarget(call, projectFiles);
    if (!target || !Node.isFunctionDeclaration(target) || visited.has(target)) continue;
    if (hasSanitizationNearby(target.getText())) continue;

    const param = target.getParameters()[argMatch.index];
    if (!param) continue;
    const paramNameNode = param.getNameNode();
    if (!Node.isIdentifier(paramNameNode) || param.isRestParameter()) continue;

    const paramName = paramNameNode.getText();
    const calleeRelFile = getRelativeFilePath(rootPath, target.getSourceFile());
    const calleeTestFile = isTestFilePath(calleeRelFile);

    const calleeTaint = collectTaint(target, {
      paramName,
      origin: argMatch.ref.origin,
      line: getNodeLine(param),
    });

    const crossingSteps: TraceStep[] = [
      ...precedingSteps,
      {
        kind: "flow",
        file: relFile,
        line: getNodeLine(call),
        note: `passed to \`${call.getExpression().getText()}(...)\` in ${calleeRelFile}`,
      },
    ];

    visited.add(target);
    traceInterproceduralSink(
      target,
      calleeTaint,
      calleeRelFile,
      crossingSteps,
      rootOrigin,
      crossedTestFile || calleeTestFile,
      hopsRemaining - 1,
      visited,
      projectFiles,
      rootPath,
      findings,
    );
    visited.delete(target);
  }
}

export const rulePromptInjectionConcat: Rule = {
  id: "AI001",
  title: "Prompt injection via user input",
  severity: "high",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];
    const projectFiles = new Set(context.sourceFiles);

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);

      for (const fnNode of sourceFile.getDescendants()) {
        if (!isFunctionLike(fnNode)) continue;
        // Skip nested functions: taint is collected per enclosing function,
        // and the outer pass already visits inner calls.
        const taint = collectTaint(fnNode);

        for (const call of fnNode.getDescendantsOfKind(SyntaxKind.CallExpression)) {
          const sink = resolveLlmSink(call);
          if (!sink) {
            // Not a direct LLM sink — if tainted data flows into a call this
            // scan can resolve to a real local function declaration, keep
            // tracing inside it (interprocedural continuation, bounded by
            // MAX_INTERPROCEDURAL_HOPS). Any resolution failure along the
            // way — ambiguous target, external function, sanitized param —
            // stops the walk rather than guessing.
            const argMatch = findTaintedArgIndex(call, taint);
            if (!argMatch) continue;

            const target = resolveLocalCallTarget(call, projectFiles);
            if (!target || !Node.isFunctionDeclaration(target)) continue;
            if (hasSanitizationNearby(target.getText())) continue;

            const param = target.getParameters()[argMatch.index];
            if (!param) continue;
            const paramNameNode = param.getNameNode();
            if (!Node.isIdentifier(paramNameNode) || param.isRestParameter()) continue;

            const paramName = paramNameNode.getText();
            const calleeRelFile = getRelativeFilePath(context.rootPath, target.getSourceFile());
            const calleeTestFile = isTestFilePath(calleeRelFile);

            const calleeTaint = collectTaint(target, {
              paramName,
              origin: argMatch.ref.origin,
              line: getNodeLine(param),
            });

            const steps: TraceStep[] = [
              { kind: "source", file: relFile, line: argMatch.ref.originLine, note: argMatch.ref.origin },
              {
                kind: "flow",
                file: relFile,
                line: getNodeLine(call),
                note: `passed to \`${call.getExpression().getText()}(...)\` in ${calleeRelFile}`,
              },
            ];

            const visited = new Set<Node>([fnNode, target]);
            traceInterproceduralSink(
              target,
              calleeTaint,
              calleeRelFile,
              steps,
              argMatch.ref.origin,
              testFile || calleeTestFile,
              MAX_INTERPROCEDURAL_HOPS - 1,
              visited,
              projectFiles,
              context.rootPath,
              findings,
            );
            continue;
          }

          for (const part of getPromptParts(call)) {
            // Untrusted input inside a *user/assistant-role* message is the
            // recommended pattern — never flag it.
            if (part.role === "user" || part.role === "assistant" || part.role === "tool") {
              continue;
            }

            if (!isDynamicComposition(part.node, taint)) continue;
            const taintedRef = findTaintedRef(part.node, taint);
            if (!taintedRef) continue;

            const isSystemRole = part.role === "system" || part.role === "developer";
            const sinkLine = getNodeLine(part.node);

            let evidence: Evidence = sink.resolved ? "proven" : "likely";
            if (testFile) evidence = demoteEvidence(evidence);
            // Param-only taint (no request object anywhere) is weaker: the
            // caller may be internal. Request-derived taint stays proven.
            if (!taintedRef.origin.startsWith("request data")) {
              evidence = demoteEvidence(evidence);
            }

            const trace: TraceStep[] = [
              {
                kind: "source",
                file: relFile,
                line: taintedRef.originLine,
                note: taintedRef.origin,
              },
            ];
            if (taintedRef.name !== taintedRef.origin && !Node.isIdentifier(part.node)) {
              trace.push({
                kind: "flow",
                file: relFile,
                line: sinkLine,
                note: `interpolated via \`${taintedRef.name}\``,
              });
            } else if (Node.isIdentifier(part.node)) {
              trace.push({
                kind: "flow",
                file: relFile,
                line: sinkLine,
                note: `passed as \`${part.node.getText()}\``,
              });
            }
            trace.push({
              kind: "sink",
              file: relFile,
              line: getNodeLine(call),
              note: `${sink.callText} — ${isSystemRole ? `${part.role} role` : `${part.role} field`} (${sink.provider})`,
            });

            findings.push({
              rule_id: "AI001",
              title: "Prompt injection via user input",
              severity: isSystemRole ? "high" : "medium",
              file: relFile,
              line: sinkLine,
              summary: isSystemRole
                ? `User-controlled data is interpolated into a ${part.role}-role prompt.`
                : "User-controlled data is mixed into the prompt string with instructions.",
              description: isSystemRole
                ? `Data originating from ${taintedRef.origin} reaches the ${part.role} prompt of a ${sink.provider} call. Anything a user types becomes privileged instructions: "ignore previous instructions" attacks work directly.`
                : `Data originating from ${taintedRef.origin} is concatenated into the prompt string of a ${sink.provider} call, mixing untrusted text with instructions in the same trust context.`,
              recommendation:
                "Keep system/developer prompts static. Pass user input as a separate user-role message: messages: [{ role: \"system\", content: SYSTEM_PROMPT }, { role: \"user\", content: userInput }].",
              confidence: evidenceConfidence(evidence),
              evidence,
              trace,
            });
          }
        }
      }
    }

    return dedupeByLocation(findings);
  },
};

function dedupeByLocation(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  const rank = { proven: 3, likely: 2, heuristic: 1 } as const;
  // Nested function scopes can yield duplicates; keep the strongest.
  const sorted = [...findings].sort((a, b) => rank[b.evidence] - rank[a.evidence]);
  for (const f of sorted) {
    const key = `${f.file}|${f.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}
