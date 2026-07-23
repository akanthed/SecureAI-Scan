import type { Severity } from "./types.js";

/**
 * Single source of truth for per-rule metadata: what the reporter, SARIF
 * output, and `explain` command render. Rule detection logic lives in the
 * rule files; everything descriptive lives here.
 */

export interface RuleCatalogEntry {
  id: string;
  title: string;
  severity: Severity;
  /** OWASP LLM Top 10 (2025) mapping, e.g. "LLM01". */
  owasp: string;
  owaspName: string;
  /** EU AI Act article most relevant to the control. */
  euAiAct?: string;
  /** OWASP Top 10 for Agentic Applications (2026) mapping, e.g. "ASI01". */
  asi?: string;
  asiName?: string;
  /** OWASP MCP Top 10 (2025) mapping, e.g. "MCP03". */
  mcpTop10?: string;
  mcpTop10Name?: string;
  impact: string;
  shortFix: string;
}

export const OWASP_LLM_TOP10: Record<string, string> = {
  LLM01: "Prompt Injection",
  LLM02: "Sensitive Information Disclosure",
  LLM03: "Supply Chain",
  LLM04: "Data and Model Poisoning",
  LLM05: "Improper Output Handling",
  LLM06: "Excessive Agency",
  LLM07: "System Prompt Leakage",
  LLM08: "Vector and Embedding Weaknesses",
  LLM09: "Misinformation",
  LLM10: "Unbounded Consumption",
};

export const OWASP_ASI_2026: Record<string, string> = {
  ASI01: "Agent Goal Hijack",
  ASI02: "Tool Misuse & Exploitation",
  ASI03: "Identity & Privilege Abuse",
  ASI04: "Agentic Supply Chain Vulnerabilities",
  ASI05: "Unexpected Code Execution",
  ASI06: "Memory & Context Poisoning",
  ASI07: "Insecure Inter-Agent Communication",
  ASI08: "Cascading Failures",
  ASI09: "Human-Agent Trust Exploitation",
  ASI10: "Rogue Agents",
};

export const OWASP_MCP_TOP10: Record<string, string> = {
  MCP01: "Token Mismanagement & Secret Exposure",
  MCP02: "Privilege Escalation via Scope Creep",
  MCP03: "Tool Poisoning",
  MCP04: "Software Supply Chain Attacks",
  MCP05: "Command Injection & Execution",
  MCP06: "Intent Flow Subversion",
  MCP07: "Insufficient Authentication & Authorization",
  MCP08: "Lack of Audit and Telemetry",
  MCP09: "Shadow MCP Servers",
  MCP10: "Context Injection & Over-Sharing",
};

/**
 * Per-rule mapping onto the two 2025/2026 OWASP frameworks. Kept separate from
 * entry() so the positional call sites stay readable; merged into RULE_CATALOG
 * below. A rule appears here only when the mapping is defensible — the
 * coverage matrix reports unmapped risks as gaps rather than stretching.
 */
const FRAMEWORK_MAP: Record<string, { asi?: string; mcpTop10?: string }> = {
  AI001: { asi: "ASI01" },
  AI003: { asi: "ASI03" },
  AI005: { asi: "ASI05" },
  AI006: { asi: "ASI02" },
  AI007: { asi: "ASI06" },
  AI010: { asi: "ASI01" },
  AI011: { asi: "ASI07" },
  AI012: { asi: "ASI05" },
  MCP001: { asi: "ASI01", mcpTop10: "MCP03" },
  MCP002: { asi: "ASI04", mcpTop10: "MCP09" },
  MCP003: { asi: "ASI02", mcpTop10: "MCP03" },
  MCP004: { asi: "ASI04", mcpTop10: "MCP04" },
  MCP005: { mcpTop10: "MCP01" },
  MCP006: { mcpTop10: "MCP07" },
  MCP007: { asi: "ASI01", mcpTop10: "MCP03" },
  MCP008: { asi: "ASI01", mcpTop10: "MCP03" },
  MCP009: { asi: "ASI02", mcpTop10: "MCP03" },
  MCP010: { asi: "ASI05", mcpTop10: "MCP05" },
  SKL001: { asi: "ASI01" },
  SKL002: { asi: "ASI01" },
  SKL003: { asi: "ASI02" },
  VEC003: { asi: "ASI06" },
  DEP001: { asi: "ASI04" },
  DEP002: { asi: "ASI04" },
  DEP003: { asi: "ASI04", mcpTop10: "MCP04" },
};

function entry(
  id: string,
  title: string,
  severity: Severity,
  owasp: string,
  impact: string,
  shortFix: string,
  euAiAct?: string,
): RuleCatalogEntry {
  const frameworks = FRAMEWORK_MAP[id] ?? {};
  return {
    id,
    title,
    severity,
    owasp,
    owaspName: OWASP_LLM_TOP10[owasp] ?? "",
    impact,
    shortFix,
    euAiAct,
    asi: frameworks.asi,
    asiName: frameworks.asi ? OWASP_ASI_2026[frameworks.asi] : undefined,
    mcpTop10: frameworks.mcpTop10,
    mcpTop10Name: frameworks.mcpTop10 ? OWASP_MCP_TOP10[frameworks.mcpTop10] : undefined,
  };
}

export const RULE_CATALOG: Record<string, RuleCatalogEntry> = {
  AI001: entry(
    "AI001",
    "Prompt injection via user input",
    "high",
    "LLM01",
    "Untrusted input becomes privileged instructions and can override system behavior.",
    "Keep system prompts static; pass user input as a user-role message.",
    "Art. 15 (robustness)",
  ),
  AI002: entry(
    "AI002",
    "Sensitive prompt or secret logged",
    "medium",
    "LLM02",
    "Prompts and secrets copied into log pipelines with weaker access control and longer retention.",
    "Log request IDs, not prompt content; never log secret values.",
    "Art. 10 (data governance)",
  ),
  AI003: entry(
    "AI003",
    "LLM call in unauthenticated request handler",
    "critical",
    "LLM10",
    "Unauthenticated callers can consume paid model capacity and reach LLM-backed features.",
    "Authenticate before invoking the model.",
    "Art. 15 (cybersecurity)",
  ),
  AI004: entry(
    "AI004",
    "Sensitive data sent to LLM",
    "high",
    "LLM02",
    "Whole-object serialization leaks PII and internal fields to a third-party API.",
    "Send only the fields the model needs; redact identifiers.",
    "Art. 10 (data governance)",
  ),
  AI005: entry(
    "AI005",
    "Unsafe LLM output handling",
    "critical",
    "LLM05",
    "Model output reaching eval/shell/SQL/HTML sinks enables code execution or XSS.",
    "Validate output against a schema; keep it away from execution sinks.",
    "Art. 15 (robustness)",
  ),
  AI006: entry(
    "AI006",
    "Excessive LLM agency",
    "critical",
    "LLM06",
    "A prompt-injected model can trigger irreversible actions (delete, pay, deploy) autonomously.",
    "Gate high-impact tools behind human confirmation or policy checks.",
    "Art. 14 (human oversight)",
  ),
  AI007: entry(
    "AI007",
    "RAG context injected into privileged prompt",
    "high",
    "LLM01",
    "A poisoned retrieved document executes as trusted instructions.",
    "Put retrieved content in user-role messages, clearly delimited as untrusted data.",
    "Art. 15 (robustness)",
  ),
  AI008: entry(
    "AI008",
    "Sensitive data in system prompt",
    "high",
    "LLM07",
    "System prompts leak via injection, logs, and provider tooling — secrets inside leak with them.",
    "Keep secrets in server-side config, never in prompt text.",
    "Art. 15 (cybersecurity)",
  ),
  AI009: entry(
    "AI009",
    "Unbounded user input sent to LLM",
    "medium",
    "LLM10",
    "Unbounded input drives cost spikes, context exhaustion, and denial of service.",
    "Cap input size and set max output tokens.",
  ),
  AI010: entry(
    "AI010",
    "Indirect prompt injection via HTTP response",
    "high",
    "LLM01",
    "Whoever controls a fetched URL can inject instructions into your model.",
    "Treat fetched content as untrusted; isolate it in a user-role message.",
    "Art. 15 (robustness)",
  ),
  AI011: entry(
    "AI011",
    "Multi-agent trust boundary violation",
    "high",
    "LLM06",
    "A compromised upstream agent escalates privileges through the agent chain.",
    "Treat inter-agent messages as untrusted; validate at each boundary.",
    "Art. 14 (human oversight)",
  ),
  AI012: entry(
    "AI012",
    "LLM output parsed without schema validation",
    "medium",
    "LLM05",
    "Unexpected shapes or injected keys propagate silently into application logic.",
    "Validate parsed JSON with a schema (Zod/Yup) or use structured output mode.",
  ),
  MCP001: entry(
    "MCP001",
    "MCP tool metadata reaches system prompt without trust-demotion",
    "critical",
    "LLM01",
    "A malicious MCP server injects instructions through tool descriptions at connect time.",
    "Validate tool metadata against an allowlist schema before prompt use.",
    "Art. 15 (cybersecurity)",
  ),
  MCP002: entry(
    "MCP002",
    "Dynamic MCP server URL from user input",
    "critical",
    "LLM03",
    "An attacker points your agent at a server they control — full agent hijack.",
    "Hardcode/allowlist MCP server URLs server-side.",
    "Art. 15 (cybersecurity)",
  ),
  MCP003: entry(
    "MCP003",
    "Unvalidated MCP tool result used as trusted LLM context",
    "high",
    "LLM05",
    "A compromised tool server injects instructions with system-level trust.",
    "Keep tool results in the tool role; validate before elevating.",
    "Art. 15 (robustness)",
  ),
  MCP004: entry(
    "MCP004",
    "MCP server runs an unpinned package",
    "high",
    "LLM03",
    "A hijacked package version executes on the next launch with local permissions.",
    "Pin exact versions in MCP config (pkg@x.y.z).",
    "Art. 15 (cybersecurity)",
  ),
  MCP005: entry(
    "MCP005",
    "Secret committed in MCP config",
    "critical",
    "LLM02",
    "API keys in shared config files are exposed to everyone with repo access.",
    "Reference env vars instead of inlining values; rotate the exposed key.",
    "Art. 15 (cybersecurity)",
  ),
  MCP006: entry(
    "MCP006",
    "MCP server over plaintext HTTP",
    "high",
    "LLM03",
    "On-path attackers can read traffic or swap in malicious tool definitions.",
    "Use https:// for all non-localhost MCP servers.",
    "Art. 15 (cybersecurity)",
  ),
  MCP007: entry(
    "MCP007",
    "Invisible Unicode in MCP tool metadata",
    "critical",
    "LLM01",
    "Invisible characters hide model-readable instructions from human review — the canonical tool-poisoning delivery mechanism.",
    "Strip invisible/bidi characters from tool names and descriptions; treat the definition as compromised until reviewed.",
    "Art. 15 (cybersecurity)",
  ),
  MCP008: entry(
    "MCP008",
    "Injection phrasing in MCP tool description",
    "high",
    "LLM01",
    "Agent-directed instructions in a description execute with trusted context — how real tool-poisoning attacks steer agents.",
    "Rewrite descriptions as plain documentation; audit third-party tool text before shipping.",
    "Art. 15 (cybersecurity)",
  ),
  MCP009: entry(
    "MCP009",
    "MCP tool description steers another tool",
    "medium",
    "LLM01",
    "Tool shadowing: one server's description manipulates calls that flow to legitimate tools it does not own.",
    "Keep each description scoped to its own tool; put orchestration policy in your agent, not server metadata.",
    "Art. 15 (cybersecurity)",
  ),
  MCP010: entry(
    "MCP010",
    "Dynamic MCP server command from untrusted input",
    "critical",
    "LLM03",
    "The MCP stdio transport executes the configured command as a real OS process — request-controlled commands/args are remote code execution.",
    "Keep MCP server commands and arguments in static, server-side configuration; never build them from request data.",
    "Art. 15 (cybersecurity)",
  ),
  SKL001: entry(
    "SKL001",
    "Invisible Unicode in agent skill file",
    "critical",
    "LLM01",
    "Invisible characters in a SKILL.md hide model-readable instructions from human review — the same delivery mechanism as MCP tool-poisoning, applied to skill files.",
    "Remove the invisible characters and audit how they were introduced; treat the skill as compromised until reviewed.",
    "Art. 15 (cybersecurity)",
  ),
  SKL002: entry(
    "SKL002",
    "Injection phrasing in agent skill file",
    "high",
    "LLM01",
    "Agent-directed instructions in a skill's description or body execute with the agent's trusted context every time the skill loads.",
    "Rewrite skill content as plain documentation; audit third-party skills before installing.",
    "Art. 15 (cybersecurity)",
  ),
  SKL003: entry(
    "SKL003",
    "Agent skill file steers another skill",
    "medium",
    "LLM01",
    "Skill shadowing: one skill's instructions manipulate when or how a different skill is used.",
    "Keep each skill file scoped to its own task; put orchestration policy in your own agent configuration, not skill content.",
    "Art. 15 (cybersecurity)",
  ),
  VEC001: entry(
    "VEC001",
    "Vector search without tenant/user access control filter",
    "high",
    "LLM08",
    "Cross-tenant document leakage through similarity search results.",
    "Filter every search by the authenticated user/tenant.",
    "Art. 10 (data governance)",
  ),
  VEC002: entry(
    "VEC002",
    "Unbounded or user-controlled vector search limit",
    "medium",
    "LLM10",
    "Attacker-controlled k enables prompt stuffing and cost exhaustion.",
    "Hardcode k server-side or clamp it to a safe maximum.",
  ),
  VEC003: entry(
    "VEC003",
    "User-controlled content ingested into vector store",
    "high",
    "LLM04",
    "RAG data poisoning: planted documents execute as injected instructions when retrieved.",
    "Sanitize and quarantine user submissions before making them retrievable.",
    "Art. 10 (data governance)",
  ),
  VEC004: entry(
    "VEC004",
    "Vector store ingestion without tenant/namespace tagging",
    "high",
    "LLM08",
    "Read-side filters have nothing to key on; cross-tenant leakage becomes unavoidable.",
    "Stamp every ingested document with a tenant/owner identifier.",
    "Art. 10 (data governance)",
  ),
  DEP001: entry(
    "DEP001",
    "Suspicious AI-related dependency",
    "medium",
    "LLM03",
    "Typosquatted or hallucinated package names deliver attacker code into the build.",
    "Verify the package name and provenance before installing.",
    "Art. 15 (cybersecurity)",
  ),
  DEP002: entry(
    "DEP002",
    "Dependency name looks similar to a popular package",
    "low",
    "LLM03",
    "A one-character-off package name can indicate typosquatting or accidental confusion with a trusted package.",
    "Confirm package ownership and intended source before installing in production.",
    "Art. 15 (cybersecurity)",
  ),
  DEP003: entry(
    "DEP003",
    "Dependency has a known-malicious or critically vulnerable release",
    "critical",
    "LLM03",
    "A documented backdoor or critical CVE in a dependency executes with your application's permissions on install or launch.",
    "Remove or update the package per the advisory; rotate credentials it could have accessed.",
    "Art. 15 (cybersecurity)",
  ),
};

export function catalogFor(ruleId: string): RuleCatalogEntry | undefined {
  return RULE_CATALOG[ruleId];
}
