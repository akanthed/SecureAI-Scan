// Safe: a call to a non-generation utility exported by an LLM SDK package is
// not an LLM call, even though it resolves through the same import.
//
// (Regression fixture: resolveLlmSink's resolved-module branch previously
// treated ANY call reached via import resolution to an LLM SDK package as an
// LLM sink, with no check on the method/function name — the GENERATION_METHODS
// filter existed but was only wired into the unresolved-name fallback path.
// Found scanning vercel/ai's own source: isToolUIPart() — a type guard, not a
// model call — is exported by the "ai" package right alongside generateText,
// and calling it inside a function with a `request` parameter fired AI003
// ("LLM call in unauthenticated request handler"). The `request` parameter
// here is an ordinary local struct, not an HTTP handler, compounding the
// false positive — but the root cause is resolveLlmSink treating a type
// guard as a generation call in the first place.)
import { isToolUIPart, type UIMessagePart } from "ai";

interface ApprovalRequest {
  toolCallId: string;
  partIndex: number;
}

export function applyToolApprovalResponse(
  message: { parts: UIMessagePart[] },
  request: ApprovalRequest,
) {
  const part = message.parts[request.partIndex];
  if (!part || !isToolUIPart(part)) {
    throw new Error(`Could not find tool approval request for ${request.toolCallId}.`);
  }
  return part;
}
