import type { Finding, Severity } from "./types.js";
import { OWASP_ASI_2026, OWASP_LLM_TOP10, OWASP_MCP_TOP10, RULE_CATALOG } from "./catalog.js";

interface ThreatBoundary {
  from: string;
  to: string;
  findings: Finding[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

const CATEGORY_LABELS: Record<string, string> = {
  AI: "AI / LLM Security",
  MCP: "MCP (Model Context Protocol)",
  SKL: "Agent Skills",
  VEC: "Vector / RAG Pipeline",
  LLM: "LLM SDK Usage",
};

function ruleCategory(ruleId: string): string {
  const prefix = ruleId.replace(/\d+$/, "");
  return CATEGORY_LABELS[prefix] ?? "General";
}

function sortBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );
}

function severityBadge(s: Severity): string {
  const map: Record<Severity, string> = {
    critical: "🔴 CRITICAL",
    high: "🟠 HIGH",
    medium: "🟡 MEDIUM",
    low: "🔵 LOW",
  };
  return map[s];
}

function buildTrustBoundaries(findings: Finding[]): ThreatBoundary[] {
  const boundaries = new Map<string, ThreatBoundary>();

  for (const f of findings) {
    let from = "User / External Input";
    let to = "LLM Model";

    if (f.rule_id.startsWith("MCP")) {
      from = "MCP Server (External Tool)";
      to = "LLM Agent";
    } else if (f.rule_id.startsWith("SKL")) {
      from = "Skill File (Local/Untrusted)";
      to = "LLM Agent Context";
    } else if (f.rule_id.startsWith("VEC")) {
      from = "Vector Store / Document Pipeline";
      to = "LLM Context / RAG";
    } else if (f.rule_id === "AI003") {
      from = "Unauthenticated Request";
      to = "LLM Model";
    } else if (f.rule_id === "AI005") {
      from = "LLM Output";
      to = "Execution Environment (eval/exec/SQL)";
    } else if (f.rule_id === "AI010") {
      from = "External HTTP Resource";
      to = "LLM Prompt";
    } else if (f.rule_id === "AI011") {
      from = "Upstream Agent Output";
      to = "Downstream Agent System Context";
    }

    const key = `${from}→${to}`;
    if (!boundaries.has(key)) {
      boundaries.set(key, { from, to, findings: [] });
    }
    boundaries.get(key)!.findings.push(f);
  }

  return [...boundaries.values()].sort(
    (a, b) =>
      Math.max(...b.findings.map((f) => SEVERITY_ORDER[f.severity])) -
      Math.max(...a.findings.map((f) => SEVERITY_ORDER[f.severity])),
  );
}

/**
 * Risks that a static scanner fundamentally cannot assess — runtime behavior,
 * process controls, or operational telemetry. Reported honestly as such
 * instead of being stretched onto a code rule.
 */
const RUNTIME_ONLY_RISKS: Record<string, string> = {
  LLM07: "runtime concern (output monitoring)",
  ASI08: "runtime concern (orchestration monitoring)",
  ASI09: "process concern (UX / approval design)",
  ASI10: "runtime concern (behavioral monitoring)",
  MCP02: "process concern (permission lifecycle review)",
  MCP08: "runtime concern (audit logging infrastructure)",
};

interface FrameworkSpec {
  title: string;
  risks: Record<string, string>;
  ruleKey: (entry: (typeof RULE_CATALOG)[string]) => string | undefined;
}

function buildCoverageMatrix(findings: Finding[]): string[] {
  const firedRules = new Set(findings.map((f) => f.rule_id));
  const frameworks: FrameworkSpec[] = [
    { title: "OWASP Top 10 for LLM Applications (2026)", risks: OWASP_LLM_TOP10, ruleKey: (e) => e.owasp },
    { title: "OWASP Top 10 for Agentic Applications (2026)", risks: OWASP_ASI_2026, ruleKey: (e) => e.asi },
    { title: "OWASP MCP Top 10 (2025)", risks: OWASP_MCP_TOP10, ruleKey: (e) => e.mcpTop10 },
  ];

  const lines: string[] = [];
  lines.push("## OWASP Framework Coverage");
  lines.push("");
  lines.push(
    "How this scan maps onto the three OWASP AI security frameworks. \"Runtime concern\" marks risks a static scanner cannot assess — cover those with runtime controls.",
  );
  lines.push("");

  for (const fw of frameworks) {
    lines.push(`### ${fw.title}`);
    lines.push("");
    lines.push("| Risk | Name | Rules | Status |");
    lines.push("|------|------|-------|--------|");
    for (const [riskId, riskName] of Object.entries(fw.risks)) {
      const rules = Object.values(RULE_CATALOG)
        .filter((e) => fw.ruleKey(e) === riskId)
        .map((e) => e.id);
      let status: string;
      if (rules.length === 0) {
        status = RUNTIME_ONLY_RISKS[riskId] ? `⚪ ${RUNTIME_ONLY_RISKS[riskId]}` : "⚪ no static rule yet";
      } else if (rules.some((r) => firedRules.has(r))) {
        status = "🔴 findings in this scan";
      } else {
        status = "🟢 covered, no findings";
      }
      lines.push(`| ${riskId} | ${riskName} | ${rules.map((r) => `\`${r}\``).join(", ") || "—"} | ${status} |`);
    }
    lines.push("");
  }

  return lines;
}

function riskGrade(findings: Finding[]): string {
  const critCount = findings.filter((f) => f.severity === "critical").length;
  const highCount = findings.filter((f) => f.severity === "high").length;
  if (critCount > 0) return "F";
  if (highCount >= 3) return "D";
  if (highCount >= 1) return "C";
  if (findings.filter((f) => f.severity === "medium").length >= 3) return "B";
  if (findings.length > 0) return "B+";
  return "A";
}

export function generateThreatModel(
  findings: Finding[],
  meta: { scannedAt: string; version: string; rootPath: string },
): string {
  const sorted = sortBySeverity(findings);
  const boundaries = buildTrustBoundaries(findings);
  const grade = riskGrade(findings);

  const byCategory = new Map<string, Finding[]>();
  for (const f of sorted) {
    const cat = ruleCategory(f.rule_id);
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(f);
  }

  const lines: string[] = [];

  lines.push("# Threat Model — AI/LLM Security");
  lines.push("");
  lines.push(`> Generated by SecureAI-Scan v${meta.version} on ${new Date(meta.scannedAt).toLocaleDateString()}`);
  lines.push(`> Scanned: \`${meta.rootPath}\``);
  lines.push("");
  lines.push("---");
  lines.push("");

  // Executive summary
  lines.push("## Executive Summary");
  lines.push("");
  lines.push(`| | |`);
  lines.push(`|---|---|`);
  lines.push(`| **Security Grade** | **${grade}** |`);
  lines.push(`| Total Findings | ${findings.length} |`);
  lines.push(`| Critical | ${findings.filter((f) => f.severity === "critical").length} |`);
  lines.push(`| High | ${findings.filter((f) => f.severity === "high").length} |`);
  lines.push(`| Medium | ${findings.filter((f) => f.severity === "medium").length} |`);
  lines.push(`| Low | ${findings.filter((f) => f.severity === "low").length} |`);
  lines.push("");

  lines.push(...buildCoverageMatrix(findings));

  if (findings.length === 0) {
    lines.push("> No security findings detected. Keep scanning on every commit to stay clean.");
    return lines.join("\n");
  }

  // Trust boundaries
  lines.push("## Trust Boundaries & Attack Surfaces");
  lines.push("");
  lines.push("The following data flows were identified as potential attack surfaces:");
  lines.push("");

  for (const boundary of boundaries) {
    const maxSev = boundary.findings.reduce(
      (max, f) => (SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[max] ? f.severity : max),
      "low" as Severity,
    );
    lines.push(`### ${boundary.from} → ${boundary.to}`);
    lines.push("");
    lines.push(`**Risk level:** ${severityBadge(maxSev)} | **${boundary.findings.length} finding(s)**`);
    lines.push("");
    for (const f of sortBySeverity(boundary.findings)) {
      lines.push(`- \`${f.rule_id}\` ${f.title} — \`${f.file}:${f.line}\``);
    }
    lines.push("");
  }

  // Attack scenarios
  lines.push("## Attack Scenarios");
  lines.push("");
  lines.push("Based on detected patterns, here are the most realistic attack chains:");
  lines.push("");

  const critAndHigh = sorted.filter(
    (f) => f.severity === "critical" || f.severity === "high",
  ).slice(0, 5);

  for (let i = 0; i < critAndHigh.length; i++) {
    const f = critAndHigh[i];
    lines.push(`### Scenario ${i + 1}: ${f.title}`);
    lines.push("");
    lines.push(`**Rule:** \`${f.rule_id}\` | **Severity:** ${severityBadge(f.severity)}`);
    lines.push(`**Location:** \`${f.file}:${f.line}\``);
    lines.push("");
    lines.push(`**What happens:**`);
    lines.push(`> ${f.description}`);
    lines.push("");
    lines.push(`**How to fix:**`);
    lines.push(`> ${f.recommendation}`);
    lines.push("");
  }

  // Findings by category
  lines.push("## All Findings by Category");
  lines.push("");

  for (const [category, catFindings] of byCategory) {
    lines.push(`### ${category}`);
    lines.push("");
    lines.push("| Rule | Severity | File | Line | Summary |");
    lines.push("|------|----------|------|------|---------|");
    for (const f of catFindings) {
      const sevLabel = f.severity.toUpperCase();
      lines.push(
        `| \`${f.rule_id}\` | ${sevLabel} | \`${f.file}\` | ${f.line} | ${f.summary} |`,
      );
    }
    lines.push("");
  }

  // Remediation priority
  lines.push("## Remediation Priority");
  lines.push("");
  lines.push("Fix in this order for maximum risk reduction:");
  lines.push("");
  const prioritized = sortBySeverity(findings).slice(0, 10);
  for (let i = 0; i < prioritized.length; i++) {
    const f = prioritized[i];
    lines.push(`${i + 1}. **${f.title}** (\`${f.rule_id}\`) — \`${f.file}:${f.line}\``);
    lines.push(`   - ${f.recommendation}`);
  }
  lines.push("");

  lines.push("---");
  lines.push("");
  lines.push("*This threat model was auto-generated. Review with your security team before sharing.*");
  lines.push(`*To re-generate: \`secureai-scan threat-model <path>\`*`);

  return lines.join("\n");
}
