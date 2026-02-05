import type { Rule } from "../types.js";
import { rulePromptInjectionConcat } from "./prompt-injection-concat.js";
import { ruleLlmUsageDetect } from "./llm-usage-detect.js";
import { ruleSensitivePromptLogging } from "./sensitive-prompt-logging.js";
import { ruleLlmBeforeAuth } from "./llm-before-auth.js";
import { ruleSensitiveDataToLlm } from "./sensitive-data-to-llm.js";

export const RULES: Rule[] = [
  rulePromptInjectionConcat,
  ruleLlmUsageDetect,
  ruleSensitivePromptLogging,
  ruleLlmBeforeAuth,
  ruleSensitiveDataToLlm,
];

export const AVAILABLE_RULE_IDS = RULES.map((rule) => rule.id);
