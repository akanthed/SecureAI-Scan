import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "./types.js";

export interface ReportMeta {
  tool: "SecureAI-Scan";
  version: string;
  scannedAt: string;
}

export interface ReportSummary {
  total: number;
  bySeverity: Record<Severity, number>;
}

export interface ReportOccurrence {
  file: string;
  line: number;
  snippet?: ReportSnippetLine[];
}

export interface ReportSnippetLine {
  lineNumber: number;
  text: string;
  highlight: boolean;
}

export interface ReportIgnoredFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  reason: string;
  annotationLine: number;
  snippet?: ReportSnippetLine[];
}

export interface ReportGroupedFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  confidenceMin: number;
  confidenceMax: number;
  reason: string;
  recommendation: string;
  occurrences: ReportOccurrence[];
}

export interface ReportModel {
  meta: ReportMeta;
  summary: ReportSummary;
  prioritizedFindings: ReportGroupedFinding[];
  allFindings: ReportGroupedFinding[];
  informational: ReportGroupedFinding[];
  ignoredFindings: ReportIgnoredFinding[];
}

type RiskPosture = "Low" | "Medium" | "High";

interface RiskCategoryGroup {
  category: string;
  findings: ReportGroupedFinding[];
}

export interface BuildReportOptions {
  rootPath?: string;
  ignoredFindings?: Array<{ finding: Finding; reason: string; annotationLine: number }>;
}

export function buildReport(
  findings: Finding[],
  meta: ReportMeta,
  options?: BuildReportOptions,
): ReportModel {
  const informational = findings.filter((finding) => isInformational(finding));
  const issues = findings.filter((finding) => !isInformational(finding));
  const snippetContext = createSnippetContext(options?.rootPath);

  const groupedIssues = groupByRule(issues, snippetContext);
  const groupedInfo = groupByRule(informational, snippetContext);
  const summary = buildSummary(issues);
  const ignoredFindings = buildIgnoredFindings(options?.ignoredFindings ?? [], snippetContext);

  const prioritized = pickTopGroups(groupedIssues, 3);

  return {
    meta,
    summary,
    prioritizedFindings: prioritized,
    allFindings: groupedIssues,
    informational: groupedInfo,
    ignoredFindings,
  };
}

export function formatReport(
  report: ReportModel,
  format: "markdown" | "md" | "html" | "json",
): string {
  const normalized = format.trim().toLowerCase();
  if (normalized === "md" || normalized === "markdown") {
    return formatMarkdown(report);
  }
  if (normalized === "html") {
    return formatHtml(report);
  }
  return JSON.stringify(report, null, 2);
}

export function formatTerminalReport(report: ReportModel, limit = 3): string {
  const lines: string[] = [];
  const posture = overallRiskPosture(report.summary);

  lines.push("SecureAI-Scan Report");
  lines.push("====================");
  lines.push(`Scanned at    : ${report.meta.scannedAt}`);
  lines.push(`Risk posture  : ${posture}`);
  lines.push(`Total issues  : ${report.summary.total}`);
  lines.push(
    `Severity      : Critical ${report.summary.bySeverity.critical} | High ${report.summary.bySeverity.high} | Medium ${report.summary.bySeverity.medium} | Low ${report.summary.bySeverity.low}`,
  );
  if (report.ignoredFindings.length > 0) {
    lines.push(`Ignored       : ${report.ignoredFindings.length}`);
  }
  if (report.informational.length > 0) {
    lines.push(`Informational : ${report.informational.length}`);
  }
  lines.push("");

  if (report.summary.total === 0) {
    lines.push("No issues found.");
    return lines.join("\n");
  }

  lines.push("Priority Security Risks");
  lines.push("-----------------------");
  const top = report.prioritizedFindings.slice(0, Math.max(0, limit));
  for (let index = 0; index < top.length; index += 1) {
    const group = top[index];
    lines.push(
      `${index + 1}. ${severityLabel(group.severity)} ${group.ruleId} - ${group.title}`,
    );
    lines.push(
      `   Confidence: ${confidenceLabel(group.confidenceMax)} (${group.confidenceMax.toFixed(2)})`,
    );
    lines.push(`   Impact    : ${impactForRule(group.ruleId)}`);
    lines.push(`   Why risky : ${group.reason}`);
  }
  lines.push("");

  if (report.summary.total > 20) {
    lines.push("Tip: use --baseline to track only new issues.");
  }

  if (top.length < report.summary.total) {
    lines.push(
      `Showing top ${top.length} of ${report.summary.total} findings. Use --output to export full report.`,
    );
  }

  if (report.informational.length > 0) {
    lines.push("");
    lines.push("Informational:");
    for (const info of report.informational) {
      const files = info.occurrences.map((o) => `${o.file}:${o.line}`).join(", ");
      lines.push(`- ℹ️ ${info.title} (Not a vulnerability) — ${files}`);
    }
  }

  return lines.join("\n");
}

function buildSummary(findings: Finding[]): ReportSummary {
  const bySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) {
    bySeverity[finding.severity] += 1;
  }
  return {
    total: findings.length,
    bySeverity,
  };
}

interface SnippetContext {
  rootPath?: string;
  linesByFile: Map<string, string[]>;
}

function createSnippetContext(rootPath?: string): SnippetContext {
  return {
    rootPath: rootPath ? path.resolve(rootPath) : undefined,
    linesByFile: new Map<string, string[]>(),
  };
}

function groupByRule(findings: Finding[], snippetContext: SnippetContext): ReportGroupedFinding[] {
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const list = grouped.get(finding.rule_id) ?? [];
    list.push(finding);
    grouped.set(finding.rule_id, list);
  }

  const result: ReportGroupedFinding[] = [];
  for (const [ruleId, group] of grouped.entries()) {
    const confidences = group.map((f) => f.confidence);
    const confidenceMin = Math.min(...confidences);
    const confidenceMax = Math.max(...confidences);
    const first = group[0];
    result.push({
      ruleId,
      title: first.title,
      severity: first.severity,
      confidenceMin,
      confidenceMax,
      reason: first.description || first.summary,
      recommendation: first.recommendation,
      occurrences: group.map((f) => ({
        file: f.file,
        line: f.line,
        snippet: readSnippet(snippetContext, f.file, f.line),
      })),
    });
  }

  return result;
}

function buildIgnoredFindings(
  ignored: Array<{ finding: Finding; reason: string; annotationLine: number }>,
  snippetContext: SnippetContext,
): ReportIgnoredFinding[] {
  return ignored.map((entry) => ({
    ruleId: entry.finding.rule_id,
    title: entry.finding.title,
    severity: entry.finding.severity,
    file: entry.finding.file,
    line: entry.finding.line,
    reason: entry.reason,
    annotationLine: entry.annotationLine,
    snippet: readSnippet(snippetContext, entry.finding.file, entry.finding.line),
  }));
}

function pickTopGroups(groups: ReportGroupedFinding[], count: number): ReportGroupedFinding[] {
  const ranked = [...groups].sort((a, b) => {
    const severityScore = severityRank(b.severity) - severityRank(a.severity);
    if (severityScore !== 0) {
      return severityScore;
    }
    return b.confidenceMax - a.confidenceMax;
  });
  return ranked.slice(0, count);
}

function isInformational(finding: Finding): boolean {
  return finding.rule_id.startsWith("LLM_");
}

function severityRank(severity: Severity): number {
  switch (severity) {
    case "critical":
      return 4;
    case "high":
      return 3;
    case "medium":
      return 2;
    case "low":
      return 1;
    default:
      return 0;
  }
}

function severityLabel(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "🔴 CRITICAL";
    case "high":
      return "🟠 HIGH";
    case "medium":
      return "🟡 MEDIUM";
    case "low":
      return "🟢 LOW";
    default:
      return severity;
  }
}

function severityLabelPlain(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
      return "LOW";
    default:
      return "UNKNOWN";
  }
}

function formatConfidenceRange(min: number, max: number): string {
  if (min === max) {
    return min.toFixed(2);
  }
  return `${min.toFixed(2)}-${max.toFixed(2)}`;
}

function overallRiskPosture(summary: ReportSummary): RiskPosture {
  if (summary.bySeverity.critical > 0 || summary.bySeverity.high > 0) {
    return "High";
  }
  if (summary.bySeverity.medium > 0) {
    return "Medium";
  }
  return "Low";
}

function riskNarrative(report: ReportModel): string {
  const posture = overallRiskPosture(report.summary);
  const { critical, high } = report.summary.bySeverity;
  if (report.summary.total === 0) {
    return "No security findings were identified. Overall risk posture is Low.";
  }
  if (posture === "High") {
    return `The scan identified ${report.summary.total} findings, including ${critical} critical and ${high} high severity item(s). Overall risk posture is High; address priority risks before deployment.`;
  }
  if (posture === "Medium") {
    return `The scan identified ${report.summary.total} findings, primarily medium severity. Overall risk posture is Medium; prioritize remediation ahead of new releases.`;
  }
  return `The scan identified ${report.summary.total} low severity finding(s). Overall risk posture is Low; monitor and address during routine maintenance.`;
}

function riskCategoryForRule(ruleId: string): string {
  switch (ruleId) {
    case "AI003":
      return "Authentication & Access Control";
    case "AI002":
    case "AI004":
      return "Data Handling & Privacy";
    case "AI001":
      return "Prompt & LLM Usage Risks";
    default:
      return "Other Security Risks";
  }
}

function groupByRiskCategory(findings: ReportGroupedFinding[]): RiskCategoryGroup[] {
  const grouped = new Map<string, ReportGroupedFinding[]>();
  for (const finding of findings) {
    const category = riskCategoryForRule(finding.ruleId);
    const list = grouped.get(category) ?? [];
    list.push(finding);
    grouped.set(category, list);
  }

  const preferredOrder = [
    "Authentication & Access Control",
    "Data Handling & Privacy",
    "Prompt & LLM Usage Risks",
    "Other Security Risks",
  ];

  const sortedCategories = [...grouped.keys()].sort((a, b) => {
    const aIndex = preferredOrder.indexOf(a);
    const bIndex = preferredOrder.indexOf(b);
    if (aIndex === -1 && bIndex === -1) {
      return a.localeCompare(b);
    }
    if (aIndex === -1) {
      return 1;
    }
    if (bIndex === -1) {
      return -1;
    }
    return aIndex - bIndex;
  });

  return sortedCategories.map((category) => {
    const items = grouped.get(category) ?? [];
    const sorted = [...items].sort((a, b) => {
      const severityScore = severityRank(b.severity) - severityRank(a.severity);
      if (severityScore !== 0) {
        return severityScore;
      }
      return b.confidenceMax - a.confidenceMax;
    });
    return { category, findings: sorted };
  });
}

function formatMarkdown(report: ReportModel): string {
  const lines: string[] = [];
  lines.push("# SecureAI-Scan Report");
  lines.push("");
  lines.push("## 1. Executive Summary");
  lines.push("");
  lines.push(`**Scanned at:** ${report.meta.scannedAt}`);
  lines.push(`**Overall Risk Posture:** ${overallRiskPosture(report.summary)}`);
  lines.push(`**Total Findings:** ${report.summary.total}`);
  lines.push(
    `**Findings by Severity:** Critical ${report.summary.bySeverity.critical} / High ${report.summary.bySeverity.high} / Medium ${report.summary.bySeverity.medium} / Low ${report.summary.bySeverity.low}`,
  );
  lines.push("");
  lines.push(riskNarrative(report));
  lines.push("");

  lines.push("## Table of Contents");
  lines.push("");
  lines.push("1. [Executive Summary](#1-executive-summary)");
  lines.push("2. [Priority Security Risks](#2-priority-security-risks)");
  lines.push("3. [Detailed Findings](#3-detailed-findings)");
  lines.push("4. [Ignored Findings](#4-ignored-findings)");
  lines.push("5. [Informational Observations](#5-informational-observations)");
  lines.push("");

  lines.push("## 2. Priority Security Risks");
  lines.push("");
  if (report.prioritizedFindings.length === 0) {
    lines.push("No issues found.");
  } else {
    for (const finding of report.prioritizedFindings) {
      lines.push(
        `**${severityLabelPlain(finding.severity)} ${finding.ruleId} — ${finding.title}**`,
      );
      lines.push(`Category: ${riskCategoryForRule(finding.ruleId)}`);
      lines.push(`Impact: ${impactForRule(finding.ruleId)}`);
      lines.push(
        `Confidence: ${confidenceLabel(finding.confidenceMax)} *(${formatConfidenceRange(
          finding.confidenceMin,
          finding.confidenceMax,
        )})*`,
      );
      lines.push("");
    }
  }

  lines.push("## 3. Detailed Findings");
  lines.push("");
  if (report.allFindings.length === 0) {
    lines.push("No issues found.");
    lines.push("");
  } else {
    const categorized = groupByRiskCategory(report.allFindings);
    for (const category of categorized) {
      lines.push(`### ${category.category}`);
      lines.push("");
      for (const group of category.findings) {
        const occurrences = group.occurrences.map((o) => `${o.file}:${o.line}`).join(", ");
        lines.push(
          `**${severityLabelPlain(group.severity)} ${group.ruleId} — ${group.title}**`,
        );
        lines.push(
          `Confidence: ${confidenceLabel(group.confidenceMax)} *(${formatConfidenceRange(
            group.confidenceMin,
            group.confidenceMax,
          )})*`,
        );
        lines.push(`Why this is risky: ${group.reason}`);
        lines.push("Why this was flagged:");
        for (const reason of whyFlaggedForRule(group.ruleId)) {
          lines.push(`- ${reason}`);
        }
        if (group.ruleId === "AI004") {
          lines.push(
            "Note: Some findings are flagged conservatively to encourage data minimization.",
          );
        }
        lines.push(`How to fix: ${group.recommendation}`);
        lines.push(`**Occurrences:** ${occurrences}`);
        for (const occ of group.occurrences) {
          lines.push(`- ${occ.file}:${occ.line}`);
          const snippet = renderMarkdownSnippet(occ.snippet);
          for (const snippetLine of snippet) {
            lines.push(snippetLine);
          }
        }
        lines.push("");
      }
    }
  }

  lines.push("## 4. Ignored Findings");
  lines.push("");
  if (report.ignoredFindings.length === 0) {
    lines.push("None.");
  } else {
    for (const ignored of report.ignoredFindings) {
      lines.push(
        `- ${severityLabelPlain(ignored.severity)} ${ignored.ruleId} ${ignored.file}:${ignored.line}`,
      );
      lines.push(`  Ignore reason: ${ignored.reason} (annotation line ${ignored.annotationLine})`);
      const snippet = renderMarkdownSnippet(ignored.snippet);
      for (const snippetLine of snippet) {
        lines.push(snippetLine);
      }
    }
  }
  lines.push("");

  lines.push("## 5. Informational Observations");
  lines.push("");
  if (report.informational.length === 0) {
    lines.push("None.");
  } else {
    for (const info of report.informational) {
      const files = info.occurrences.map((o) => `${o.file}:${o.line}`).join(", ");
      lines.push(`- ${info.title} (Not a vulnerability) — ${files}`);
    }
  }
  lines.push("");

  lines.push("## Next Steps");
  lines.push("");
  lines.push("- Create a baseline to reduce noise over time.");
  lines.push("- Fix Critical and High issues first.");
  lines.push("- Add ignore annotations for findings you have reviewed.");
  lines.push("- Consider running SecureAI-Scan in CI to catch regressions earlier.");
  lines.push("");

  return lines.join("\n");
}

function formatHtml(report: ReportModel): string {
  const posture = overallRiskPosture(report.summary);
  const toc = [
    `<li><a href="#summary">1. Executive Summary</a></li>`,
    `<li><a href="#fix-first">2. Priority Security Risks</a></li>`,
    `<li><a href="#critical-high">3. Detailed Findings</a></li>`,
    `<li><a href="#ignored">4. Ignored Findings</a></li>`,
    `<li><a href="#informational">5. Informational Observations</a></li>`,
  ].join("");

  const prioritized = report.prioritizedFindings
    .map(
      (f) =>
        `<div class="priority-card ${f.severity}">
          <div class="finding-header">
            <span class="severity-tag ${f.severity}">${severityLabelPlain(f.severity)}</span>
            <span class="finding-title">${escapeHtml(f.ruleId)} — ${escapeHtml(f.title)}</span>
          </div>
          <div class="finding-meta">Category: ${escapeHtml(riskCategoryForRule(f.ruleId))}</div>
          <div class="finding-impact">Impact: ${escapeHtml(impactForRule(f.ruleId))}</div>
          <div class="confidence">Confidence: ${confidenceLabel(
            f.confidenceMax,
          )} <span class="confidence-value">(${formatConfidenceRange(
            f.confidenceMin,
            f.confidenceMax,
          )})</span></div>
        </div>`,
    )
    .join("");

  const categorized = groupByRiskCategory(report.allFindings);
  const detailed = categorized
    .map(
      (category) =>
        `<div class="category-block">
          <h3>${escapeHtml(category.category)}</h3>
          ${category.findings.map((f) => renderGroup(f)).join("")}
        </div>`,
    )
    .join("");

  const info = report.informational
    .map((f) => {
      const files = f.occurrences.map((o) => `${escapeHtml(o.file)}:${o.line}`).join(", ");
      return `<li>${escapeHtml(
        f.title,
      )} <span class="info-tag">Not a vulnerability</span><br/><span class="muted">${files}</span></li>`;
    })
    .join("");

  const ignored = report.ignoredFindings
    .map((finding) => {
      return `<li>
        <strong>${severityLabelPlain(finding.severity)} ${escapeHtml(finding.ruleId)}</strong>
        ${escapeHtml(finding.file)}:${finding.line}<br/>
        <span class="muted">Ignore reason: ${escapeHtml(finding.reason)} (annotation line ${
          finding.annotationLine
        })</span>
        ${renderHtmlSnippet(finding.snippet)}
      </li>`;
    })
    .join("");

  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>SecureAI-Scan Report</title>
    <style>
      :root {
        --bg: #ffffff;
        --card: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #e2e8f0;
        --critical: #b91c1c;
        --high: #c2410c;
        --medium: #a16207;
        --low: #15803d;
      }
      body {
        margin: 0;
        font-family: system-ui, -apple-system, Segoe UI, sans-serif;
        background: var(--bg);
        color: var(--text);
        font-size: 15px;
        line-height: 1.5;
      }
      header {
        background: var(--card);
        border-bottom: 1px solid var(--border);
        padding: 22px 24px 12px;
      }
      .container {
        padding: 20px 24px 48px;
        max-width: 960px;
        margin: 0 auto;
      }
      .page-title {
        font-size: 20px;
        font-weight: 700;
        letter-spacing: 0.01em;
      }
      .report-section {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 18px;
        margin-top: 18px;
      }
      .section-title {
        margin: 0 0 12px;
        font-size: 20px;
        font-weight: 700;
      }
      .meta-line {
        color: var(--muted);
        font-size: 13px;
      }
      .toc-list {
        margin: 0;
        padding-left: 18px;
      }
      .toc-list li {
        margin: 6px 0;
      }
      .toc-list a {
        color: var(--text);
        text-decoration: none;
        border-bottom: 1px solid var(--border);
      }
      .toc-list a:hover {
        border-bottom-color: var(--text);
      }
      .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px;
        margin-top: 12px;
      }
      .summary-item {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 12px;
      }
      .summary-label {
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
      }
      .summary-value {
        font-size: 18px;
        font-weight: 700;
        margin-top: 6px;
      }
      .risk.high { color: var(--critical); }
      .risk.medium { color: var(--medium); }
      .risk.low { color: var(--low); }
      .muted {
        color: var(--muted);
      }
      .priority-list {
        display: grid;
        gap: 12px;
      }
      .priority-card,
      .finding-card {
        border: 1px solid var(--border);
        border-left: 4px solid var(--border);
        border-radius: 10px;
        padding: 14px;
        margin-top: 12px;
      }
      .priority-card.critical,
      .finding-card.critical {
        border-left-color: var(--critical);
      }
      .priority-card.high,
      .finding-card.high {
        border-left-color: var(--high);
      }
      .priority-card.medium,
      .finding-card.medium {
        border-left-color: var(--medium);
      }
      .priority-card.low,
      .finding-card.low {
        border-left-color: var(--low);
      }
      .finding-header {
        display: flex;
        align-items: center;
        gap: 10px;
        font-weight: 600;
      }
      .finding-title {
        font-size: 16px;
      }
      .severity-tag {
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        font-weight: 700;
        border: 1px solid var(--border);
        border-radius: 999px;
        padding: 2px 8px;
        color: var(--text);
        background: #f8fafc;
      }
      .severity-tag.critical { color: var(--critical); border-color: rgba(185, 28, 28, 0.35); }
      .severity-tag.high { color: var(--high); border-color: rgba(194, 65, 12, 0.35); }
      .severity-tag.medium { color: var(--medium); border-color: rgba(161, 98, 7, 0.35); }
      .severity-tag.low { color: var(--low); border-color: rgba(21, 128, 61, 0.35); }
      .finding-meta,
      .finding-impact {
        margin-top: 6px;
        color: var(--muted);
        font-size: 13px;
      }
      .confidence {
        margin-top: 6px;
        color: var(--muted);
        font-size: 12px;
      }
      .confidence-value {
        opacity: 0.7;
        margin-left: 4px;
      }
      .finding-body {
        margin-top: 10px;
      }
      .why-flagged {
        margin: 6px 0 0;
        padding-left: 18px;
        color: var(--muted);
        font-size: 13px;
      }
      .note {
        margin-top: 8px;
        color: var(--muted);
        font-size: 13px;
      }
      .callout {
        margin-top: 12px;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 10px 12px;
        background: #f8fafc;
      }
      .callout-title {
        font-weight: 600;
        font-size: 12px;
        letter-spacing: 0.04em;
        text-transform: uppercase;
        color: var(--muted);
        margin-bottom: 6px;
      }
      .occurrences {
        margin-top: 10px;
        font-size: 12px;
        color: var(--muted);
      }
      .occurrences ul {
        margin: 6px 0 0;
        padding-left: 18px;
      }
      .snippet {
        margin: 8px 0 0;
        background: #f8fafc;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 8px;
        overflow-x: auto;
      }
      .code-line {
        font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        font-size: 12px;
        display: grid;
        grid-template-columns: 42px 1fr;
        column-gap: 8px;
        padding: 1px 0;
      }
      .code-line .num {
        color: var(--muted);
        text-align: right;
      }
      .code-line.is-hit {
        background: #eef2ff;
      }
      .ignored-list {
        padding-left: 18px;
      }
      .ignored-list li {
        margin-bottom: 10px;
      }
      .category-block h3 {
        margin: 18px 0 8px;
        font-size: 16px;
      }
      .informational {
        color: var(--muted);
        font-size: 13px;
      }
      .informational ul {
        padding-left: 18px;
      }
      .info-tag {
        display: inline-block;
        margin-left: 6px;
        padding: 2px 6px;
        border-radius: 999px;
        border: 1px solid var(--border);
        font-size: 10px;
        color: var(--muted);
      }
      .next-steps {
        color: var(--muted);
        font-size: 13px;
      }
      .next-steps ul {
        padding-left: 18px;
      }
    </style>
  </head>
  <body>
    <header>
      <div class="page-title">SecureAI-Scan Report</div>
      <div class="muted">Scanned at ${report.meta.scannedAt}</div>
    </header>
    <div class="container">
      <section id="summary" class="report-section">
        <h2 class="section-title">1. Executive Summary</h2>
        <div class="meta-line">Scanned at ${report.meta.scannedAt}</div>
        <div class="summary-grid">
          <div class="summary-item">
            <div class="summary-label">Overall Risk Posture</div>
            <div class="summary-value risk ${posture.toLowerCase()}">${posture}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">Total Findings</div>
            <div class="summary-value">${report.summary.total}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">Critical</div>
            <div class="summary-value">${report.summary.bySeverity.critical}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">High</div>
            <div class="summary-value">${report.summary.bySeverity.high}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">Medium</div>
            <div class="summary-value">${report.summary.bySeverity.medium}</div>
          </div>
          <div class="summary-item">
            <div class="summary-label">Low</div>
            <div class="summary-value">${report.summary.bySeverity.low}</div>
          </div>
        </div>
        <p class="finding-body">${escapeHtml(riskNarrative(report))}</p>
      </section>

      <section class="report-section">
        <h2 class="section-title">Table of Contents</h2>
        <ol class="toc-list">${toc}</ol>
      </section>

      <section id="fix-first" class="report-section">
        <h2 class="section-title">2. Priority Security Risks</h2>
        <div class="priority-list">${prioritized || "<div class=\"muted\">No issues found.</div>"}</div>
      </section>

      <section id="critical-high" class="report-section">
        <h2 class="section-title">3. Detailed Findings</h2>
        ${detailed || "<p class=\"muted\">No issues found.</p>"}
      </section>

      <section id="ignored" class="report-section informational">
        <h2 class="section-title">4. Ignored Findings</h2>
        <ul class="ignored-list">${ignored || "<li class=\"muted\">None.</li>"}</ul>
      </section>

      <section id="informational" class="report-section informational">
        <h2 class="section-title">5. Informational Observations</h2>
        <ul>${info || "<li class=\"muted\">None.</li>"}</ul>
      </section>

      <section class="report-section next-steps">
        <h2 class="section-title">Next Steps</h2>
        <ul>
          <li>Create a baseline to reduce noise over time.</li>
          <li>Fix Critical and High issues first.</li>
          <li>Add ignore annotations for findings you have reviewed.</li>
          <li>Consider running SecureAI-Scan in CI to catch regressions earlier.</li>
        </ul>
      </section>
    </div>
  </body>
</html>`;
}

function renderGroup(group: ReportGroupedFinding): string {
  const occurrences = group.occurrences
    .map((o) => {
      const location = `${escapeHtml(o.file)}:${o.line}`;
      const snippet = renderHtmlSnippet(o.snippet);
      return `<li>${location}${snippet}</li>`;
    })
    .join("");
  const whyFlagged = whyFlaggedForRule(group.ruleId)
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join("");
  const note =
    group.ruleId === "AI004"
      ? `<div class="note">Note: Some findings are flagged conservatively to encourage data minimization.</div>`
      : "";
  return `
    <div class="finding-card ${group.severity}">
      <div class="finding-header">
        <span class="severity-tag ${group.severity}">${severityLabelPlain(
          group.severity,
        )}</span>
        <span class="finding-title">${escapeHtml(group.ruleId)} — ${escapeHtml(group.title)}</span>
      </div>
      <div class="confidence">Confidence: ${confidenceLabel(
        group.confidenceMax,
      )} <span class="confidence-value">(${formatConfidenceRange(
        group.confidenceMin,
        group.confidenceMax,
      )})</span></div>
      <div class="finding-body">${escapeHtml(group.reason)}</div>
      <div class="finding-meta"><strong>Why this was flagged</strong></div>
      <ul class="why-flagged">${whyFlagged}</ul>
      ${note}
      <div class="callout">
        <div class="callout-title">How to fix</div>
        <div>${escapeHtml(group.recommendation)}</div>
      </div>
      <div class="occurrences"><strong>Occurrences:</strong><ul>${occurrences}</ul></div>
    </div>
  `;
}

function whyFlaggedForRule(ruleId: string): string[] {
  switch (ruleId) {
    case "AI001":
      return [
        "User input is blended into prompt construction.",
        "Prompt text is dynamically assembled at runtime.",
        "Input safety controls are not visible at this location.",
      ];
    case "AI002":
      return [
        "Prompt or model output is sent to logging sinks.",
        "Logged data can include sensitive request content.",
        "Redaction or minimization is not evident near the log call.",
      ];
    case "AI003":
      return [
        "An LLM call appears in a request handler path.",
        "Authentication checks are not observed before the call.",
        "Unauthenticated execution could trigger model actions.",
      ];
    case "AI004":
      return [
        "High-context objects are passed directly to the model.",
        "Payload content likely includes user or session attributes.",
        "Field-level minimization is not evident at the call site.",
      ];
    default:
      return [
        "Static rule pattern matched this code path.",
        "Input validation or containment controls were not confirmed.",
      ];
  }
}

function readSnippet(
  context: SnippetContext,
  filePath: string,
  issueLine: number,
): ReportSnippetLine[] | undefined {
  const lines = readFileLines(context, filePath);
  if (!lines || issueLine <= 0 || issueLine > lines.length) {
    return undefined;
  }

  const start = Math.max(1, issueLine - 2);
  const end = Math.min(lines.length, issueLine + 2);
  const snippet: ReportSnippetLine[] = [];

  for (let lineNumber = start; lineNumber <= end; lineNumber += 1) {
    snippet.push({
      lineNumber,
      text: lines[lineNumber - 1],
      highlight: lineNumber === issueLine,
    });
  }

  return snippet;
}

function readFileLines(context: SnippetContext, findingPath: string): string[] | undefined {
  const filePath = resolveFindingPath(context.rootPath, findingPath);
  const key = filePath.toLowerCase();
  if (context.linesByFile.has(key)) {
    return context.linesByFile.get(key);
  }

  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    const lines = raw.split(/\r?\n/);
    context.linesByFile.set(key, lines);
    return lines;
  } catch {
    context.linesByFile.set(key, []);
    return undefined;
  }
}

function resolveFindingPath(rootPath: string | undefined, findingPath: string): string {
  if (path.isAbsolute(findingPath)) {
    return findingPath;
  }
  return rootPath ? path.resolve(rootPath, findingPath) : path.resolve(findingPath);
}

function renderMarkdownSnippet(snippet?: ReportSnippetLine[]): string[] {
  if (!snippet || snippet.length === 0) {
    return [];
  }
  const lines = ["```ts"];
  for (const line of snippet) {
    const marker = line.highlight ? ">>" : "  ";
    lines.push(`${marker} ${line.lineNumber.toString().padStart(4, " ")} | ${line.text}`);
  }
  lines.push("```");
  return lines;
}

function renderHtmlSnippet(snippet?: ReportSnippetLine[]): string {
  if (!snippet || snippet.length === 0) {
    return "";
  }
  const lines = snippet
    .map((line) => {
      const cls = line.highlight ? "code-line is-hit" : "code-line";
      return `<div class="${cls}"><span class="num">${line.lineNumber}</span><span class="txt">${escapeHtml(
        line.text,
      )}</span></div>`;
    })
    .join("");
  return `<pre class="snippet">${lines}</pre>`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function confidenceLabel(value: number): string {
  if (value >= 0.75) {
    return "High";
  }
  if (value >= 0.5) {
    return "Medium";
  }
  return "Low";
}

function impactForRule(ruleId: string): string {
  switch (ruleId) {
    case "AI001":
      return "Untrusted input can override or manipulate system instructions.";
    case "AI002":
      return "Sensitive prompt or response data can leak through logs.";
    case "AI003":
      return "Unauthenticated users can trigger LLM actions.";
    case "AI004":
      return "User or session data may be exposed to third-party models.";
    default:
      return "Security risk may be triggered in production usage.";
  }
}
