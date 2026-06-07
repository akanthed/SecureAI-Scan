export interface ConfidenceInputs {
  directUserInput?: boolean;
  stringConcatOrTemplate?: boolean;
  requestObjectSource?: boolean;
  confirmedLlmCall?: boolean;
  isTestFile?: boolean;
  hasInputSanitization?: boolean;
  isEmbeddingCall?: boolean;
  multipleSignals?: boolean;
}

export function calculateConfidence(inputs: ConfidenceInputs): number {
  let score = 0;

  if (inputs.confirmedLlmCall) score += 0.2;
  if (inputs.directUserInput) score += 0.3;
  if (inputs.stringConcatOrTemplate) score += 0.2;
  if (inputs.requestObjectSource) score += 0.15;
  if (inputs.multipleSignals) score += 0.15;

  // Reducers — lower confidence when context suggests lower risk
  if (inputs.isTestFile) score -= 0.3;
  if (inputs.hasInputSanitization) score -= 0.35;
  if (inputs.isEmbeddingCall) score -= 0.4;

  return Math.min(1, Math.max(0.1, Number(score.toFixed(2))));
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

export function hasSanitizationNearby(text: string): boolean {
  const lower = text.toLowerCase();
  return (
    lower.includes("sanitize") ||
    lower.includes("escape") ||
    lower.includes("encode") ||
    lower.includes("validate") ||
    lower.includes("allowlist") ||
    lower.includes("whitelist") ||
    lower.includes("strip") ||
    lower.includes("purify")
  );
}
