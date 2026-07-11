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

function entry(
  id: string,
  title: string,
  severity: Severity,
  owasp: string,
  impact: string,
  shortFix: string,
  euAiAct?: string,
): RuleCatalogEntry {
  return { id, title, severity, owasp, owaspName: OWASP_LLM_TOP10[owasp] ?? "", impact, shortFix, euAiAct };
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
};

export function catalogFor(ruleId: string): RuleCatalogEntry | undefined {
  return RULE_CATALOG[ruleId];
}
