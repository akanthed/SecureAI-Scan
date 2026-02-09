export type PromptRiskLevel = "Low" | "Medium" | "High";

export interface PromptRiskResult {
  level: PromptRiskLevel;
  reasons: string[];
  suggestions: string[];
}

const OVERRIDE_PATTERNS: RegExp[] = [
  /\bignore (all |any )?(previous|prior|above) instructions?\b/i,
  /\bdisregard (all |any )?(previous|prior|above) instructions?\b/i,
  /\bdeveloper mode\b/i,
  /\bjailbreak\b/i,
  /\bbypass (safety|guardrails?|restrictions?)\b/i,
];

const USER_INPUT_PATTERNS: RegExp[] = [
  /\$\{\s*(user(Input)?|input|message|prompt|query)\s*\}/i,
  /\{\{\s*(user(Input)?|input|message|prompt|query)\s*\}\}/i,
  /\b(raw|untrusted)\s+user\s+input\b/i,
  /\bappend user input\b/i,
];

const DANGEROUS_SYSTEM_PATTERNS: RegExp[] = [
  /\breveal (secrets?|keys?|passwords?)\b/i,
  /\bexfiltrat(e|ion)\b/i,
  /\bdisable (safety|policy|guardrails?)\b/i,
  /\bno restrictions?\b/i,
  /\bexecute (shell|command|script)\b/i,
];

export function evaluatePromptRisk(promptText: string): PromptRiskResult {
  const normalized = promptText.trim();
  if (normalized.length === 0) {
    return {
      level: "Low",
      reasons: ["Prompt text is empty."],
      suggestions: ["Provide the exact prompt text to evaluate risk."],
    };
  }

  const reasons: string[] = [];
  let score = 0;

  if (USER_INPUT_PATTERNS.some((pattern) => pattern.test(normalized))) {
    score += 2;
    reasons.push("Prompt appears to include unescaped user-controlled input.");
  }

  if (OVERRIDE_PATTERNS.some((pattern) => pattern.test(normalized))) {
    score += 2;
    reasons.push("Prompt includes instruction-override language (ignore/bypass style).");
  }

  if (DANGEROUS_SYSTEM_PATTERNS.some((pattern) => pattern.test(normalized))) {
    score += 1;
    reasons.push("Prompt contains potentially dangerous system-level keywords.");
  }

  if (normalized.length > 600) {
    score += 1;
    reasons.push("Very long prompts increase review complexity and hidden risk.");
  }

  const level: PromptRiskLevel = score >= 4 ? "High" : score >= 2 ? "Medium" : "Low";

  const suggestions = buildSuggestions(level, reasons);
  if (reasons.length === 0) {
    reasons.push("No high-risk heuristic patterns were detected.");
  }

  return { level, reasons, suggestions };
}

function buildSuggestions(level: PromptRiskLevel, reasons: string[]): string[] {
  const suggestions: string[] = [];
  if (reasons.some((reason) => reason.includes("unescaped user-controlled input"))) {
    suggestions.push("Encode or delimit user input before including it in prompts.");
  }
  if (reasons.some((reason) => reason.includes("override language"))) {
    suggestions.push("Remove ignore/bypass instructions and enforce strict role boundaries.");
  }
  if (reasons.some((reason) => reason.includes("system-level keywords"))) {
    suggestions.push("Avoid prompts that request secrets, policy bypass, or shell execution.");
  }
  if (level === "Low" && suggestions.length === 0) {
    suggestions.push("Keep prompts explicit, minimal, and separated by role.");
  }
  if (suggestions.length === 0) {
    suggestions.push("Review prompt templates with security-focused code review.");
  }
  return suggestions;
}
