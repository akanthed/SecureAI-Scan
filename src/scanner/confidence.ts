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

export function isTestFilePath(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return (
    normalized.includes(".test.") ||
    normalized.includes(".spec.") ||
    normalized.includes("/__tests__/") ||
    normalized.includes("/test/") ||
    normalized.includes("/tests/") ||
    normalized.endsWith(".test.ts") ||
    normalized.endsWith(".spec.ts")
  );
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

/** True when any token of the identifier is in the given token set. */
export function hasToken(name: string, tokens: Set<string>): boolean {
  return identifierTokens(name).some((t) => tokens.has(t));
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
