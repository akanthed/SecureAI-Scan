import type { Evidence } from "./types.js";

/**
 * Numeric confidence derived from the evidence tier. Kept for JSON/report
 * compatibility and for --min-confidence; the tier is the source of truth.
 */
export function evidenceConfidence(evidence: Evidence): number {
  switch (evidence) {
    case "proven":
      return 0.9;
    case "likely":
      return 0.65;
    case "heuristic":
      return 0.35;
  }
}

/** Downgrade an evidence tier by one step (e.g. test file, sanitizer nearby). */
export function demoteEvidence(evidence: Evidence): Evidence {
  if (evidence === "proven") return "likely";
  return "heuristic";
}

// Whole path segments that indicate test/example/demo/fixture code rather
// than production logic. Matched per-segment (not substring) so a real
// production directory like "attestation" or "protest-bot" never collides,
// while hyphenated conventions real repos actually use — "ecosystem-tests",
// "integration-tests", "test-fixtures", "example-app" — and top-level dirs
// (no leading "/" in a relative path, e.g. "tests/foo.ts") are still caught.
// Both affix positions are needed: suffix-only missed "test-fixtures", the
// layout this repo itself uses.
// "evals?" added after cloudflare/mcp-server-cloudflare's packages/eval-tools/
// tripped AI001: an LLM-as-judge scoring harness (vitest-evals) that
// interpolates its own `input`/`expected`/`output` triple into a prompt to
// grade factuality — structurally identical to real prompt injection, but a
// same-repo eval harness, not a request handler.
const NON_PRODUCTION_WORD = "tests?|e2e|examples?|demos?|samples?|fixtures?|mocks?|stubs?|evals?";
const NON_PRODUCTION_SEGMENT = new RegExp(
  `^(?:__(?:${NON_PRODUCTION_WORD})__|playground|(?:${NON_PRODUCTION_WORD})` +
    `|.*[-_](?:${NON_PRODUCTION_WORD})|(?:${NON_PRODUCTION_WORD})[-_].*)$`,
);

export function isTestFilePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  if (normalized.includes(".test.") || normalized.includes(".spec.")) {
    return true;
  }
  return normalized.split("/").some((segment) => NON_PRODUCTION_SEGMENT.test(segment));
}

/**
 * Tokenize an identifier into lowercase words: splits camelCase, snake_case,
 * kebab-case and digits. "requireAuth" → ["require","auth"], "oauthRedirect"
 * → ["oauth","redirect"] (so "auth" no longer matches inside "oauth"/"author").
 */
export function identifierTokens(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .split(/[^A-Za-z]+/)
    .filter((t) => t.length > 0)
    .map((t) => t.toLowerCase());
}

const SANITIZER_TOKENS = new Set([
  "sanitize",
  "sanitized",
  "sanitizer",
  "escape",
  "escaped",
  "redact",
  "redacted",
  "allowlist",
  "whitelist",
  "purify",
]);

/**
 * Word-boundary sanitizer detection. Intentionally narrower than before:
 * generic words like "validate", "strip", "encode" matched far too much
 * (any comment or unrelated call suppressed real findings).
 */
export function hasSanitizationNearby(text: string): boolean {
  const words = text.split(/[^A-Za-z]+/);
  for (const word of words) {
    for (const token of identifierTokens(word)) {
      if (SANITIZER_TOKENS.has(token)) return true;
    }
  }
  return false;
}
