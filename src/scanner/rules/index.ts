import type { Rule } from "../types.js";
import { rulePromptInjectionConcat } from "./prompt-injection-concat.js";
import { ruleLlmUsageDetect } from "./llm-usage-detect.js";
import { ruleSensitivePromptLogging } from "./sensitive-prompt-logging.js";
import { ruleLlmBeforeAuth } from "./llm-before-auth.js";
import { ruleSensitiveDataToLlm } from "./sensitive-data-to-llm.js";
import { ruleUnsafeOutputHandling } from "./unsafe-output-handling.js";
import { ruleExcessiveAgency } from "./excessive-agency.js";
import { ruleRagContextInjection } from "./rag-context-injection.js";
import { ruleSystemPromptLeakage } from "./system-prompt-leakage.js";
import { ruleUnboundedLlmInput } from "./unbounded-llm-input.js";

export const RULES: Rule[] = [
  rulePromptInjectionConcat,
  ruleLlmUsageDetect,
  ruleSensitivePromptLogging,
  ruleLlmBeforeAuth,
  ruleSensitiveDataToLlm,
  ruleUnsafeOutputHandling,
  ruleExcessiveAgency,
  ruleRagContextInjection,
  ruleSystemPromptLeakage,
  ruleUnboundedLlmInput,
];

export const AVAILABLE_RULE_IDS = RULES.map((rule) => rule.id);
