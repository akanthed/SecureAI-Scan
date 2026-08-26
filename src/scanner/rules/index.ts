import type { Rule } from "../types.js";
import { rulePromptInjectionConcat } from "./prompt-injection-concat.js";
import { ruleSensitivePromptLogging } from "./sensitive-prompt-logging.js";
import { ruleLlmBeforeAuth } from "./llm-before-auth.js";
import { ruleSensitiveDataToLlm } from "./sensitive-data-to-llm.js";
import { ruleUnsafeOutputHandling } from "./unsafe-output-handling.js";
import { ruleExcessiveAgency } from "./excessive-agency.js";
import { ruleRagContextInjection } from "./rag-context-injection.js";
import { ruleSystemPromptLeakage } from "./system-prompt-leakage.js";
import { ruleUnboundedLlmInput } from "./unbounded-llm-input.js";
// New AI rules
import { ruleIndirectPromptInjection } from "./indirect-prompt-injection.js";
import { ruleMultiagentTrustBoundary } from "./multiagent-trust-boundary.js";
import { ruleUnvalidatedStructuredOutput } from "./unvalidated-structured-output.js";
// MCP rules
import { ruleMcpToolDescInjection } from "./mcp-tool-desc-injection.js";
import { ruleMcpDynamicServerUrl } from "./mcp-dynamic-server-url.js";
import { ruleMcpDynamicServerCommand } from "./mcp-dynamic-server-command.js";
import { ruleMcpUnvalidatedToolResult } from "./mcp-unvalidated-tool-result.js";
import {
  ruleMcpCrossToolShadowing,
  ruleMcpInjectionPhrases,
  ruleMcpInvisibleUnicode,
} from "./mcp-tool-poisoning.js";
import { ruleMcpUntrustedToolSource } from "./mcp-untrusted-tool-source.js";
// Vector/RAG rules
import { ruleVecSearchNoAccessControl } from "./vec-search-no-access-control.js";
import { ruleVecUnboundedSearch } from "./vec-unbounded-search.js";
import { ruleVecUserIngestion } from "./vec-user-ingestion.js";
import { ruleVecIngestionNoNamespace } from "./vec-ingestion-no-namespace.js";

export const RULES: Rule[] = [
  // Core AI/LLM rules (AI001–AI009)
  rulePromptInjectionConcat,
  ruleSensitivePromptLogging,
  ruleLlmBeforeAuth,
  ruleSensitiveDataToLlm,
  ruleUnsafeOutputHandling,
  ruleExcessiveAgency,
  ruleRagContextInjection,
  ruleSystemPromptLeakage,
  ruleUnboundedLlmInput,
  // Extended AI rules (AI010–AI012)
  ruleIndirectPromptInjection,
  ruleMultiagentTrustBoundary,
  ruleUnvalidatedStructuredOutput,
  // MCP rules (MCP001–MCP003)
  ruleMcpToolDescInjection,
  ruleMcpDynamicServerUrl,
  ruleMcpDynamicServerCommand,
  ruleMcpUnvalidatedToolResult,
  // MCP tool-poisoning rules (MCP007–MCP009)
  ruleMcpInvisibleUnicode,
  ruleMcpInjectionPhrases,
  ruleMcpCrossToolShadowing,
  // MCP tool-source rule (MCP011)
  ruleMcpUntrustedToolSource,
  // Vector/RAG rules (VEC001–VEC004)
  ruleVecSearchNoAccessControl,
  ruleVecUnboundedSearch,
  ruleVecUserIngestion,
  ruleVecIngestionNoNamespace,
];

// Config-file rules implemented outside the AST rule engine (mcp-config-scanner).
export const CONFIG_RULE_IDS = ["MCP004", "MCP005", "MCP006"];

// LiteLLM proxy config.yaml rules implemented outside the AST rule engine
// (litellm-config-scanner).
export const LITELLM_CONFIG_RULE_IDS = ["LLC001", "LLC002", "LLC003"];

// Agent Skill (SKILL.md) rules implemented outside the AST rule engine (skill-scanner).
export const SKILL_RULE_IDS = [
  "SKL001", "SKL002", "SKL003", "SKL004", "SKL005", "SKL006", "SKL007", "SKL008", "SKL009", "SKL010",
];

// Dependency rules implemented in dependency-guard (DEP001/DEP002 are opt-in
// via --check-dependencies; DEP003 runs on every scan from the offline
// advisory list).
export const DEPENDENCY_RULE_IDS = ["DEP001", "DEP002", "DEP003"];

export const AVAILABLE_RULE_IDS = [
  ...RULES.map((rule) => rule.id),
  ...CONFIG_RULE_IDS,
  ...LITELLM_CONFIG_RULE_IDS,
  ...SKILL_RULE_IDS,
  ...DEPENDENCY_RULE_IDS,
];
