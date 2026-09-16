import { Node, SyntaxKind } from "ts-morph";
import type { Evidence, Finding, Rule, RuleContext } from "../types.js";
import { getCallsWithin, getFileFunctions, getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import {
  evidenceConfidence,
  demoteEvidence,
  identifierTokens,
  isTestFilePath,
} from "../confidence.js";
import { resolveLlmSink } from "./llm-rule-utils.js";

// Exact-token auth vocabulary. Token matching means `requireAuth` and
// `verifyJwt` match while `author()` and `oauthRedirect()` do not.
const AUTH_TOKENS = new Set(["auth", "authenticate", "authenticated", "authorization", "authorize", "login", "jwt"]);
const AUTH_TOKEN_PAIRS: Array<[string, string]> = [
  ["verify", "token"],
  ["verify", "session"],
  ["verify", "user"],
  ["get", "session"],
  ["require", "user"],
  ["current", "user"],
  ["check", "permission"],
];

function nameLooksLikeAuth(name: string): boolean {
  const tokens = identifierTokens(name);
  if (tokens.some((t) => AUTH_TOKENS.has(t))) return true;
  const set = new Set(tokens);
  return AUTH_TOKEN_PAIRS.some(([a, b]) => set.has(a) && set.has(b));
}

function isAuthCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) return false;
  return nameLooksLikeAuth(node.getExpression().getText());
}

function isRequestHandler(node: Node): boolean {
  if (
    !Node.isFunctionDeclaration(node) &&
    !Node.isFunctionExpression(node) &&
    !Node.isArrowFunction(node) &&
    !Node.isMethodDeclaration(node)
  ) {
    return false;
  }
  return node.getParameters().some((param) => {
    const name = param.getNameNode().getText().toLowerCase();
    return name === "req" || name === "request";
  });
}

/** The route registration or wrapper around the handler may carry the auth middleware. */
function surroundingHasAuth(handler: Node): boolean {
  const enclosingCall = handler.getFirstAncestorByKind(SyntaxKind.CallExpression);
  if (enclosingCall && nameLooksLikeAuth(enclosingCall.getText().slice(0, 400))) {
    // e.g. router.post("/chat", requireAuth, handler) or withAuth(handler)
    for (const arg of enclosingCall.getArguments()) {
      if (arg === handler) continue;
      if (nameLooksLikeAuth(arg.getText())) return true;
    }
    if (nameLooksLikeAuth(enclosingCall.getExpression().getText())) return true;
  }
  return false;
}

export const ruleLlmBeforeAuth: Rule = {
  id: "AI003",
  title: "LLM call in unauthenticated request handler",
  severity: "critical",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const relFile = getRelativeFilePath(context.rootPath, sourceFile);
      const testFile = isTestFilePath(relFile);
      const functionNodes = getFileFunctions(sourceFile).filter(isRequestHandler);

      for (const fn of functionNodes) {
        if (surroundingHasAuth(fn)) continue;

        const calls = getCallsWithin(fn);
        let authSeen = false;

        for (const call of calls) {
          if (isAuthCall(call)) {
            authSeen = true;
            continue;
          }

          const sink = resolveLlmSink(call);
          if (!sink) continue;
          if (authSeen) continue;

          // Auth may live in middleware this rule can't see — that one
          // unobservable hop is why this is "likely", never "proven".
          let evidence: Evidence = sink.resolved ? "likely" : "heuristic";
          if (testFile) evidence = demoteEvidence(evidence);

          findings.push({
            rule_id: "AI003",
            title: "LLM call in unauthenticated request handler",
            severity: "critical",
            file: relFile,
            line: getNodeLine(call),
            summary: `${/^[aeiou]/i.test(sink.provider) ? "An" : "A"} ${sink.provider} call runs in a request handler with no visible auth check before it.`,
            description:
              "No authentication call, auth middleware, or session check was found between the request entry point and the LLM invocation. If auth is not enforced elsewhere (gateway/middleware), unauthenticated callers can consume paid model capacity and reach LLM-backed functionality.",
            recommendation:
              "Authenticate before invoking the model (e.g. requireAuth(req) / verifyJwt / middleware on the route). If auth is enforced upstream, suppress with: // secureai-ignore AI003: auth enforced by <where>.",
            confidence: evidenceConfidence(evidence),
            evidence,
            trace: [
              {
                kind: "source",
                file: relFile,
                line: getNodeLine(fn),
                note: "request handler entry (req/request parameter)",
              },
              {
                kind: "sink",
                file: relFile,
                line: getNodeLine(call),
                note: `${sink.callText} (${sink.provider}) — no auth check observed before this line`,
              },
            ],
          });
        }
      }
    }

    return findings;
  },
};
