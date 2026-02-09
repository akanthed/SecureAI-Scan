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

export interface ReportBaselineDiff {
  created: boolean;
  baselinePath: string;
  baselineCount: number;
  currentCount: number;
  newOrRegressedCount: number;
  unchangedCount: number;
}

export interface ReportModel {
  meta: ReportMeta;
  summary: ReportSummary;
  baselineDiff?: ReportBaselineDiff;
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
  baselineDiff?: ReportBaselineDiff;
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
    baselineDiff: options?.baselineDiff,
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

  if (top.length < report.summary.total) {
    lines.push(
      `Showing top ${top.length} of ${report.summary.total} findings. Use --output to export full report.`,
    );
  }

  if (report.informational.length > 0) {
    lines.push("");
    lines.push("Informational:");
    for (const info of report.informational) {
      const preview = summarizeOccurrences(info.occurrences, 5);
      lines.push(`- INFO ${info.title} (Not a vulnerability)`);
      for (const location of preview.shown) {
        lines.push(`  ${location}`);
      }
      if (preview.remaining > 0) {
        lines.push(`  ...and ${preview.remaining} more`);
      }
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
      return "CRITICAL";
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
      return "LOW";
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
  const posture = overallRiskPosture(report.summary);
  const decision = releaseDecision(report.summary);
  const mustFixCount = report.summary.bySeverity.critical + report.summary.bySeverity.high;
  const topActions = buildTopActions(report.prioritizedFindings, 3);

  lines.push("# SecureAI-Scan Report");
  lines.push("");
  lines.push("## 1. Executive Summary");
  lines.push("");
  lines.push(`**Scanned at:** ${report.meta.scannedAt}`);
  lines.push(`**Overall Risk Posture:** ${posture}`);
  lines.push(`**Total Findings:** ${report.summary.total}`);
  lines.push(
    `**Findings by Severity:** Critical ${report.summary.bySeverity.critical} / High ${report.summary.bySeverity.high} / Medium ${report.summary.bySeverity.medium} / Low ${report.summary.bySeverity.low}`,
  );
  if (report.baselineDiff) {
    if (report.baselineDiff.created) {
      lines.push(`**Baseline:** Created in this run (captured ${report.baselineDiff.currentCount} findings)`);
    } else {
      lines.push(
        `**Baseline Diff:** New or regressed ${report.baselineDiff.newOrRegressedCount} / Unchanged ${report.baselineDiff.unchangedCount} (baseline ${report.baselineDiff.baselineCount}, current ${report.baselineDiff.currentCount})`,
      );
    }
  }
  lines.push("");
  lines.push(riskNarrative(report));
  lines.push("");
  lines.push("### Release Decision");
  lines.push("");
  lines.push(`- Status: **${decision.status}**`);
  lines.push(`- Must-fix before release: **${mustFixCount}**`);
  if (topActions.length > 0) {
    lines.push("Top actions:");
    for (const action of topActions) {
      lines.push(`- ${action}`);
    }
  }
  lines.push("");

  lines.push("## Table of Contents");
  lines.push("");
  lines.push("1. [Executive Summary](#1-executive-summary)");
  lines.push("2. [Priority Security Risks](#2-priority-security-risks)");
  lines.push("3. [Immediate Fix Plan](#3-immediate-fix-plan)");
  lines.push("4. [Detailed Findings](#4-detailed-findings)");
  lines.push("5. [Ignored Findings](#5-ignored-findings)");
  lines.push("6. [Informational Observations](#6-informational-observations)");
  lines.push("");

  lines.push("## 2. Priority Security Risks");
  lines.push("");
  if (report.prioritizedFindings.length === 0) {
    lines.push("No issues found.");
  } else {
    for (const finding of report.prioritizedFindings) {
      lines.push(
        `**${severityLabelPlain(finding.severity)} ${finding.ruleId} - ${finding.title}**`,
      );
      lines.push(`Impact: ${impactForRule(finding.ruleId)}`);
      lines.push(`How to fix now: ${shortFixForRule(finding.ruleId, finding.recommendation)}`);
      lines.push(
        `Confidence: ${confidenceLabel(finding.confidenceMax)} *(${formatConfidenceRange(
          finding.confidenceMin,
          finding.confidenceMax,
        )})*`,
      );
      lines.push("");
    }
  }

  lines.push("## 3. Immediate Fix Plan");
  lines.push("");
  if (topActions.length === 0) {
    lines.push("No immediate actions required.");
  } else {
    for (const action of topActions) {
      lines.push(`- ${action}`);
    }
  }
  lines.push("");

  lines.push("## 4. Detailed Findings");
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
        const evidence = splitEvidenceOccurrences(group.occurrences, 2);
        const exploit = exploitPathForRule(group.ruleId);
        lines.push(
          `**${severityLabelPlain(group.severity)} ${group.ruleId} - ${group.title}**`,
        );
        lines.push(`Impact: ${impactForRule(group.ruleId)}`);
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
        lines.push("Exploit path:");
        lines.push(`- Trigger: ${exploit.trigger}`);
        lines.push(`- Exposure: ${exploit.exposure}`);
        lines.push(`- Impact: ${exploit.impact}`);
        lines.push(`- Mitigation: ${exploit.mitigation}`);
        lines.push(`How to fix: ${group.recommendation}`);
        lines.push("**Evidence:**");
        if (evidence.primary.length === 0) {
          lines.push("- None.");
        } else {
          for (const occ of evidence.primary) {
            lines.push(`- ${occ.file}:${occ.line}`);
            const snippet = renderMarkdownSnippet(occ.snippet);
            for (const snippetLine of snippet) {
              lines.push(snippetLine);
            }
          }
        }
        if (evidence.overflow.length > 0) {
          lines.push(`Additional occurrences (${evidence.overflow.length}):`);
          for (const occ of evidence.overflow) {
            lines.push(`- ${occ.file}:${occ.line}`);
          }
        }
        lines.push("");
      }
    }
  }

  lines.push("## 5. Ignored Findings");
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

  lines.push("## 6. Informational Observations");
  lines.push("");
  if (report.informational.length === 0) {
    lines.push("None.");
  } else {
    for (const info of report.informational) {
      const preview = summarizeOccurrences(info.occurrences, 6);
      lines.push(`### ${info.title} (Not a vulnerability)`);
      lines.push("");
      lines.push(`Occurrences: ${info.occurrences.length}`);
      for (const location of preview.shown) {
        lines.push(`- ${location}`);
      }
      if (preview.remaining > 0) {
        lines.push(`- ...and ${preview.remaining} more`);
      }
      lines.push("");
    }
  }
  lines.push("");

  lines.push("## Next Steps");
  lines.push("");
  lines.push("- Create a baseline to reduce noise over time.");
  lines.push("- Fix Critical and High issues first.");
  lines.push("- Add ignore annotations for findings you have reviewed.");
  lines.push("- Run SecureAI-Scan in CI to catch regressions earlier.");
  lines.push("");

  return lines.join("\n");
}

function formatHtml(report: ReportModel): string {
  const posture = overallRiskPosture(report.summary);
  const decision = releaseDecision(report.summary);
  const mustFixCount = report.summary.bySeverity.critical + report.summary.bySeverity.high;
  const topActions = buildTopActions(report.prioritizedFindings, 3);
  const riskMix = buildRiskMixConic(report.summary);
  const riskPercents = riskPercentages(report.summary);
  const toc = [
    `<li><a href="#summary">1. Executive Summary</a></li>`,
    `<li><a href="#fix-first">2. Priority Security Risks</a></li>`,
    `<li><a href="#fix-plan">3. Immediate Fix Plan</a></li>`,
    `<li><a href="#critical-high">4. Detailed Findings</a></li>`,
    `<li><a href="#ignored">5. Ignored Findings</a></li>`,
    `<li><a href="#informational">6. Informational Observations</a></li>`,
  ].join("");

  const baselineDigest = report.baselineDiff
    ? report.baselineDiff.created
      ? `<div class="decision-row"><span>Baseline</span><strong>Created in this run</strong></div>
       <div class="decision-row muted"><span>Captured findings</span><strong>${report.baselineDiff.currentCount}</strong></div>`
      : `<div class="decision-row"><span>Baseline Diff</span><strong>New/regressed ${report.baselineDiff.newOrRegressedCount} | Unchanged ${report.baselineDiff.unchangedCount}</strong></div>
       <div class="decision-row muted"><span>Comparison</span><strong>Baseline ${report.baselineDiff.baselineCount} | Current ${report.baselineDiff.currentCount}</strong></div>`
    : `<div class="decision-row muted"><span>Baseline Diff</span><strong>Not active</strong></div>`;

  const decisionActions = topActions.map((action) => `<li>${escapeHtml(action)}</li>`).join("");

  const prioritized = report.prioritizedFindings
    .map(
      (f) =>
        `<div class="priority-card ${f.severity}">
          <div class="finding-header">
            <span class="severity-tag ${f.severity}">${severityLabelPlain(f.severity)}</span>
            <span class="finding-title">${escapeHtml(f.ruleId)} - ${escapeHtml(f.title)}</span>
          </div>
          <div class="finding-meta">Category: ${escapeHtml(riskCategoryForRule(f.ruleId))}</div>
          <div class="finding-impact">Impact: ${escapeHtml(impactForRule(f.ruleId))}</div>
          <div class="finding-fix"><strong>How to fix now:</strong> ${escapeHtml(
            shortFixForRule(f.ruleId, f.recommendation),
          )}</div>
          <div class="confidence"><span class="confidence-pill">Confidence</span> ${confidenceLabel(
            f.confidenceMax,
          )} <span class="confidence-value">(${formatConfidenceRange(
            f.confidenceMin,
            f.confidenceMax,
          )})</span></div>
        </div>`,
    )
    .join("");

  const quickActions = report.prioritizedFindings
    .slice(0, 3)
    .map(
      (finding) =>
        `<li><span class="severity-tag small ${finding.severity}">${severityLabelPlain(
          finding.severity,
        )}</span> ${escapeHtml(finding.ruleId)}: ${escapeHtml(shortFixForRule(finding.ruleId, finding.recommendation))}</li>`,
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
      const preview = summarizeOccurrences(f.occurrences, 6);
      const locations = preview.shown
        .map((location) => `<li>${escapeHtml(location)}</li>`)
        .join("");
      const remaining =
        preview.remaining > 0
          ? `<li class="muted">...and ${preview.remaining} more</li>`
          : "";
      return `<li>
        ${escapeHtml(f.title)} <span class="info-tag">Not a vulnerability</span>
        <div class="muted">Occurrences: ${f.occurrences.length}</div>
        <ul class="info-locations">${locations}${remaining}</ul>
      </li>`;
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
        --bg: #edf2f7;
        --card: #ffffff;
        --text: #0f172a;
        --muted: #475569;
        --border: #d7e1ee;
        --border-strong: #c5d2e3;
        --shadow: 0 12px 32px rgba(15, 23, 42, 0.08);
        --accent-1: #0ea5e9;
        --accent-2: #22c55e;
        --critical: #c1272d;
        --high: #d46f06;
        --medium: #9a6a00;
        --low: #1f8a4d;
      }
      body {
        margin: 0;
        font-family: "Segoe UI", "Helvetica Neue", Arial, system-ui, -apple-system, sans-serif;
        background: var(--bg);
        color: var(--text);
        font-size: 16px;
        line-height: 1.6;
        position: relative;
      }
      body::before {
        content: "";
        position: fixed;
        inset: 0;
        background-image:
          radial-gradient(circle at 20% 18%, rgba(14, 165, 233, 0.08), transparent 26%),
          radial-gradient(circle at 84% 14%, rgba(34, 197, 94, 0.08), transparent 24%);
        pointer-events: none;
        z-index: -1;
      }
      header {
        background: var(--card);
        border-bottom: 1px solid var(--border);
        padding: 20px 24px 12px;
        box-shadow: 0 1px 0 rgba(15, 23, 42, 0.03);
        position: static;
      }
      header::after {
        content: "";
        display: block;
        margin-top: 12px;
        height: 3px;
        border-radius: 999px;
        background: linear-gradient(90deg, var(--critical), var(--high), var(--accent-1), var(--accent-2));
        background-size: 220% 220%;
        animation: moveGradient 7s linear infinite;
      }
      .container {
        width: min(1320px, calc(100vw - 32px));
        padding: 16px 0 48px;
        margin: 0 auto;
      }
      .page-title {
        font-size: 30px;
        font-weight: 760;
        line-height: 1.2;
        letter-spacing: -0.02em;
      }
      .header-meta {
        margin-top: 8px;
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
      }
      .header-chip {
        border: 1px solid var(--border);
        border-radius: 999px;
        padding: 5px 11px;
        color: var(--muted);
        font-size: 12px;
        background: #f8fafc;
        transition: transform 220ms ease, box-shadow 220ms ease;
      }
      .header-chip:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 14px rgba(15, 23, 42, 0.08);
      }
      .report-section {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 18px;
        margin-top: 18px;
        box-shadow: var(--shadow);
        animation: riseIn 420ms ease both;
      }
      .report-section:nth-of-type(2) { animation-delay: 45ms; }
      .report-section:nth-of-type(3) { animation-delay: 90ms; }
      .report-section:nth-of-type(4) { animation-delay: 135ms; }
      .report-section:nth-of-type(5) { animation-delay: 180ms; }
      .report-section:nth-of-type(6) { animation-delay: 225ms; }
      .report-section:nth-of-type(7) { animation-delay: 270ms; }
      @media (prefers-reduced-motion: reduce) {
        .report-section {
          animation: none;
        }
      }
      @keyframes riseIn {
        from { opacity: 0; transform: translateY(9px); }
        to { opacity: 1; transform: translateY(0); }
      }
      @keyframes moveGradient {
        0% { background-position: 0% 50%; }
        100% { background-position: 220% 50%; }
      }
      .section-title {
        margin: 0 0 12px;
        font-size: 28px;
        font-weight: 700;
        line-height: 1.15;
        letter-spacing: -0.02em;
      }
      .section-title.small {
        font-size: 22px;
      }
      .meta-line {
        color: var(--muted);
        font-size: 14px;
      }
      .toc-list {
        margin: 0;
        padding-left: 0;
        list-style: none;
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
        gap: 6px;
      }
      .toc-list a {
        display: block;
        color: var(--text);
        text-decoration: none;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 6px 9px;
        font-size: 14px;
        background: #ffffff;
      }
      .toc-list a:hover {
        border-color: var(--border-strong);
        background: #f0f7ff;
      }
      .summary-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
        gap: 12px;
        margin-top: 12px;
      }
      .summary-layout {
        display: grid;
        grid-template-columns: minmax(0, 1fr) 300px;
        gap: 14px;
        align-items: stretch;
      }
      .summary-item {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 12px;
        background: #ffffff;
      }
      .summary-label {
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: var(--muted);
      }
      .summary-value {
        font-size: 32px;
        font-weight: 740;
        line-height: 1;
        margin-top: 8px;
      }
      .risk-panel {
        border: 1px solid var(--border);
        border-radius: 12px;
        background: #ffffff;
        padding: 12px;
        display: grid;
        grid-template-columns: 120px minmax(0, 1fr);
        gap: 12px;
        align-items: center;
      }
      .risk-donut {
        width: 112px;
        height: 112px;
        border-radius: 50%;
        display: grid;
        place-items: center;
        box-shadow: inset 0 0 0 1px rgba(15, 23, 42, 0.05);
        animation: spinIn 820ms cubic-bezier(.2,.8,.2,1);
      }
      .risk-donut-hole {
        width: 64px;
        height: 64px;
        border-radius: 50%;
        background: #ffffff;
        border: 1px solid var(--border);
        display: grid;
        place-items: center;
        text-align: center;
        font-size: 11px;
        color: var(--muted);
        line-height: 1.2;
      }
      .risk-donut-hole strong {
        display: block;
        color: var(--text);
        font-size: 13px;
        margin-top: 2px;
      }
      .risk-legend {
        margin: 0;
        padding-left: 0;
        list-style: none;
      }
      .risk-legend li {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
        font-size: 12px;
        margin-bottom: 7px;
      }
      .risk-legend .left {
        display: inline-flex;
        align-items: center;
        gap: 6px;
      }
      .risk-dot {
        width: 10px;
        height: 10px;
        border-radius: 50%;
      }
      .risk-dot.critical { background: var(--critical); }
      .risk-dot.high { background: var(--high); }
      .risk-dot.medium { background: var(--medium); }
      .risk-dot.low { background: var(--low); }
      @keyframes spinIn {
        from { transform: rotate(-110deg) scale(0.9); opacity: 0; }
        to { transform: rotate(0deg) scale(1); opacity: 1; }
      }
      .risk.high { color: var(--critical); }
      .risk.medium { color: var(--medium); }
      .risk.low { color: var(--low); }
      .muted {
        color: var(--muted);
      }
      .toc-section {
        background: #f7fafc;
        border-color: var(--border-strong);
        position: static;
      }
      .decision-panel {
        margin-top: 14px;
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 14px;
        background: #f8fbff;
      }
      .decision-grid {
        display: grid;
        grid-template-columns: 1fr 1fr;
        gap: 12px;
      }
      .decision-status,
      .decision-details {
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 10px 12px;
        background: #ffffff;
      }
      .decision-status-label {
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 11px;
        color: var(--muted);
      }
      .decision-status-value {
        margin-top: 6px;
        font-size: 20px;
        font-weight: 700;
      }
      .decision-status-value.block {
        color: var(--critical);
      }
      .decision-status-value.caution {
        color: var(--high);
      }
      .decision-status-value.ready {
        color: var(--low);
      }
      .decision-row {
        font-size: 13px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
      }
      .decision-row + .decision-row {
        margin-top: 6px;
      }
      .decision-row strong {
        color: var(--text);
      }
      .decision-actions {
        margin: 10px 0 0;
        padding-left: 18px;
      }
      .decision-actions li {
        margin-bottom: 4px;
      }
      .priority-list {
        display: grid;
        gap: 12px;
      }
      .priority-card,
      .finding-card {
        border: 1px solid var(--border);
        border-left: 6px solid var(--border);
        border-radius: 12px;
        padding: 16px;
        margin-top: 12px;
        background: #ffffff;
        box-shadow: 0 3px 12px rgba(15, 23, 42, 0.04);
        transition: transform 220ms ease, box-shadow 220ms ease, border-color 220ms ease;
      }
      .priority-card:hover,
      .finding-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 10px 24px rgba(15, 23, 42, 0.09);
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
        font-size: 23px;
        line-height: 1.3;
        font-weight: 700;
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
      .severity-tag.critical {
        animation: heartbeat 2600ms ease-in-out infinite;
      }
      @media (prefers-reduced-motion: reduce) {
        .severity-tag.critical {
          animation: none;
        }
      }
      @keyframes heartbeat {
        0%, 100% { transform: scale(1); }
        10% { transform: scale(1.03); }
        20% { transform: scale(1); }
      }
      .finding-meta,
      .finding-impact {
        margin-top: 8px;
        color: var(--muted);
        font-size: 14px;
      }
      .finding-fix {
        margin-top: 10px;
        padding: 9px 11px;
        border: 1px solid var(--border);
        border-radius: 8px;
        background: #f8fbff;
        font-size: 14px;
      }
      .confidence {
        margin-top: 10px;
        color: var(--muted);
        font-size: 14px;
      }
      .confidence-pill {
        font-size: 11px;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        border: 1px solid var(--border);
        border-radius: 999px;
        padding: 1px 7px;
        margin-right: 8px;
      }
      .confidence-value {
        opacity: 0.7;
        margin-left: 4px;
      }
      .finding-body {
        margin-top: 10px;
      }
      .why-flagged,
      .exploit-path,
      .compact-occurrences {
        margin: 6px 0 0;
        padding-left: 18px;
        color: var(--muted);
        font-size: 14px;
      }
      .note {
        margin-top: 8px;
        color: var(--muted);
        font-size: 14px;
      }
      .callout {
        margin-top: 0;
        border: 1px solid var(--border);
        border-radius: 8px;
        padding: 12px;
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
        font-size: 14px;
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
        margin: 18px 0 10px;
        font-size: 24px;
      }
      .finding-main {
        margin-top: 10px;
        display: grid;
        grid-template-columns: minmax(0, 1fr) 320px;
        gap: 12px;
        align-items: start;
      }
      .finding-problem {
        min-width: 0;
      }
      .quick-actions ul {
        margin: 8px 0 0;
        padding-left: 18px;
      }
      .quick-actions li {
        margin-bottom: 8px;
      }
      .severity-tag.small {
        font-size: 10px;
        padding: 1px 6px;
        margin-right: 6px;
      }
      .informational {
        color: var(--muted);
        font-size: 14px;
      }
      .informational ul {
        padding-left: 18px;
      }
      .info-locations {
        margin-top: 6px;
        padding-left: 18px;
      }
      .info-locations li {
        margin-bottom: 4px;
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
        font-size: 14px;
      }
      .next-steps ul {
        padding-left: 18px;
      }
      @media (max-width: 940px) {
        .container {
          width: calc(100vw - 20px);
          padding-top: 12px;
        }
        .summary-layout {
          grid-template-columns: 1fr;
        }
        .decision-grid {
          grid-template-columns: 1fr;
        }
        .finding-main {
          grid-template-columns: 1fr;
        }
        .risk-panel {
          grid-template-columns: 1fr;
          justify-items: center;
        }
        .finding-title {
          font-size: 19px;
        }
        .section-title {
          font-size: 24px;
        }
      }
      @media print {
        body {
          background: #ffffff;
          font-size: 12pt;
        }
        header {
          position: static;
          box-shadow: none;
        }
        .toc-section {
          position: static;
        }
        .report-section {
          break-inside: avoid;
          box-shadow: none;
          border-color: #d1d5db;
        }
        .snippet {
          white-space: pre-wrap;
        }
      }
    </style>
  </head>
  <body>
    <header>
      <div class="page-title">SecureAI-Scan Report</div>
      <div class="meta-line">Scanned at ${report.meta.scannedAt}</div>
      <div class="header-meta">
        <span class="header-chip">Risk posture: ${posture}</span>
        <span class="header-chip">Total findings: ${report.summary.total}</span>
        <span class="header-chip">Critical: ${report.summary.bySeverity.critical}</span>
        <span class="header-chip">High: ${report.summary.bySeverity.high}</span>
      </div>
    </header>
    <div class="container">
      <section id="summary" class="report-section">
        <h2 class="section-title">1. Executive Summary</h2>
        <div class="meta-line">Scanned at ${report.meta.scannedAt}</div>
        <div class="summary-layout">
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
          <aside class="risk-panel">
            <div class="risk-donut" style="background: conic-gradient(${riskMix});">
              <div class="risk-donut-hole">
                Risk
                <strong>${posture}</strong>
              </div>
            </div>
            <ul class="risk-legend">
              <li>
                <span class="left"><span class="risk-dot critical"></span>Critical</span>
                <span>${report.summary.bySeverity.critical} (${riskPercents.critical}%)</span>
              </li>
              <li>
                <span class="left"><span class="risk-dot high"></span>High</span>
                <span>${report.summary.bySeverity.high} (${riskPercents.high}%)</span>
              </li>
              <li>
                <span class="left"><span class="risk-dot medium"></span>Medium</span>
                <span>${report.summary.bySeverity.medium} (${riskPercents.medium}%)</span>
              </li>
              <li>
                <span class="left"><span class="risk-dot low"></span>Low</span>
                <span>${report.summary.bySeverity.low} (${riskPercents.low}%)</span>
              </li>
            </ul>
          </aside>
        </div>
        <p class="finding-body">${escapeHtml(riskNarrative(report))}</p>
        <div class="decision-panel">
          <h3 class="section-title small">Release Decision</h3>
          <div class="decision-grid">
            <div class="decision-status">
              <div class="decision-status-label">Status</div>
              <div class="decision-status-value ${decision.cssClass}">${decision.status}</div>
            </div>
            <div class="decision-details">
              <div class="decision-row"><span>Must-fix before release</span><strong>${mustFixCount}</strong></div>
              ${baselineDigest}
            </div>
          </div>
          <ul class="decision-actions">${decisionActions || "<li class=\"muted\">No urgent actions.</li>"}</ul>
        </div>
      </section>

      <section class="report-section toc-section">
        <h2 class="section-title small">Table of Contents</h2>
        <ol class="toc-list">${toc}</ol>
      </section>

      <section id="fix-first" class="report-section">
        <h2 class="section-title">2. Priority Security Risks</h2>
        <div class="priority-list">${prioritized || "<div class=\"muted\">No issues found.</div>"}</div>
      </section>

      <section id="fix-plan" class="report-section quick-actions">
        <h2 class="section-title">3. Immediate Fix Plan</h2>
        <ul>${quickActions || "<li class=\"muted\">No immediate actions.</li>"}</ul>
      </section>

      <section id="critical-high" class="report-section">
        <h2 class="section-title">4. Detailed Findings</h2>
        ${detailed || "<p class=\"muted\">No issues found.</p>"}
      </section>

      <section id="ignored" class="report-section informational">
        <h2 class="section-title">5. Ignored Findings</h2>
        <ul class="ignored-list">${ignored || "<li class=\"muted\">None.</li>"}</ul>
      </section>

      <section id="informational" class="report-section informational">
        <h2 class="section-title">6. Informational Observations</h2>
        <ul>${info || "<li class=\"muted\">None.</li>"}</ul>
      </section>

      <section class="report-section next-steps">
        <h2 class="section-title">Next Steps</h2>
        <ul>
          <li>Create a baseline to reduce noise over time.</li>
          <li>Fix Critical and High issues first.</li>
          <li>Add ignore annotations for findings you have reviewed.</li>
          <li>Run SecureAI-Scan in CI to catch regressions earlier.</li>
        </ul>
      </section>
    </div>
  </body>
</html>`;
}

function renderGroup(group: ReportGroupedFinding): string {
  const evidence = splitEvidenceOccurrences(group.occurrences, 2);
  const primaryOccurrences = evidence.primary
    .map((occurrence) => {
      const location = `${escapeHtml(occurrence.file)}:${occurrence.line}`;
      const snippet = renderHtmlSnippet(occurrence.snippet);
      return `<li>${location}${snippet}</li>`;
    })
    .join("");
  const overflowOccurrences = evidence.overflow
    .map((occurrence) => `<li>${escapeHtml(occurrence.file)}:${occurrence.line}</li>`)
    .join("");
  const whyFlagged = whyFlaggedForRule(group.ruleId)
    .map((reason) => `<li>${escapeHtml(reason)}</li>`)
    .join("");
  const exploitPath = exploitPathForRule(group.ruleId);
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
        <span class="finding-title">${escapeHtml(group.ruleId)} - ${escapeHtml(group.title)}</span>
      </div>
      <div class="confidence"><span class="confidence-pill">Confidence</span> ${confidenceLabel(
        group.confidenceMax,
      )} <span class="confidence-value">(${formatConfidenceRange(
        group.confidenceMin,
        group.confidenceMax,
      )})</span></div>
      <div class="finding-main">
        <div class="finding-problem">
          <div class="finding-body">${escapeHtml(group.reason)}</div>
          <div class="finding-meta"><strong>Why this was flagged</strong></div>
          <ul class="why-flagged">${whyFlagged}</ul>
          <div class="finding-meta"><strong>Exploit path</strong></div>
          <ul class="exploit-path">
            <li><strong>Trigger:</strong> ${escapeHtml(exploitPath.trigger)}</li>
            <li><strong>Exposure:</strong> ${escapeHtml(exploitPath.exposure)}</li>
            <li><strong>Impact:</strong> ${escapeHtml(exploitPath.impact)}</li>
            <li><strong>Mitigation:</strong> ${escapeHtml(exploitPath.mitigation)}</li>
          </ul>
          ${note}
        </div>
        <div class="callout">
          <div class="callout-title">How to fix</div>
          <div>${escapeHtml(group.recommendation)}</div>
        </div>
      </div>
      <div class="occurrences"><strong>Evidence (with snippets):</strong><ul>${primaryOccurrences || "<li>None.</li>"}</ul></div>
      ${
        overflowOccurrences
          ? `<div class="occurrences"><strong>Additional occurrences (${evidence.overflow.length}):</strong><ul class="compact-occurrences">${overflowOccurrences}</ul></div>`
          : ""
      }
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

interface ReleaseDecision {
  status: string;
  cssClass: "block" | "caution" | "ready";
}

function releaseDecision(summary: ReportSummary): ReleaseDecision {
  if (summary.bySeverity.critical > 0 || summary.bySeverity.high > 0) {
    return { status: "Block Release", cssClass: "block" };
  }
  if (summary.bySeverity.medium > 0) {
    return { status: "Proceed with Caution", cssClass: "caution" };
  }
  return { status: "Ready for Release", cssClass: "ready" };
}

function shortFixForRule(ruleId: string, fallback: string): string {
  switch (ruleId) {
    case "AI001":
      return "Separate untrusted input from system/developer instructions.";
    case "AI002":
      return "Stop logging raw prompts/responses and redact sensitive fields.";
    case "AI003":
      return "Enforce authentication and authorization before any LLM call.";
    case "AI004":
      return "Minimize and redact user/session fields before model calls.";
    default:
      return fallback;
  }
}

function buildTopActions(findings: ReportGroupedFinding[], count: number): string[] {
  return findings
    .slice(0, count)
    .map(
      (finding) =>
        `${severityLabelPlain(finding.severity)} ${finding.ruleId}: ${shortFixForRule(finding.ruleId, finding.recommendation)}`,
    );
}

interface ExploitPath {
  trigger: string;
  exposure: string;
  impact: string;
  mitigation: string;
}

function exploitPathForRule(ruleId: string): ExploitPath {
  switch (ruleId) {
    case "AI001":
      return {
        trigger: "Untrusted text is concatenated directly into a prompt template.",
        exposure: "System instruction boundaries can be overridden.",
        impact: "Model behavior can be manipulated outside intended policy.",
        mitigation: "Isolate user input in data fields and sanitize before inclusion.",
      };
    case "AI002":
      return {
        trigger: "Prompt or model output is written to logs.",
        exposure: "Secrets and PII can land in log stores.",
        impact: "Sensitive data can be retained or accessed by unintended roles.",
        mitigation: "Remove raw prompt logging or apply strict redaction filters.",
      };
    case "AI003":
      return {
        trigger: "LLM call runs before authentication checks complete.",
        exposure: "Unauthorized callers can invoke model behavior.",
        impact: "Protected workflows may be triggered without valid identity.",
        mitigation: "Gate request handlers with auth checks before model execution.",
      };
    case "AI004":
      return {
        trigger: "High-context objects are sent directly to LLM APIs.",
        exposure: "User/session attributes may be transmitted externally.",
        impact: "Potential privacy and compliance exposure of sensitive fields.",
        mitigation: "Send least-privilege payloads with explicit allowlisted fields.",
      };
    default:
      return {
        trigger: "Rule pattern matched source code behavior.",
        exposure: "Security boundary could be bypassed at runtime.",
        impact: "Unexpected model-side behavior or data exposure may occur.",
        mitigation: "Apply least-privilege access, validation, and data minimization.",
      };
  }
}

function splitEvidenceOccurrences(
  occurrences: ReportOccurrence[],
  withSnippetLimit: number,
): { primary: ReportOccurrence[]; overflow: ReportOccurrence[] } {
  return {
    primary: occurrences.slice(0, withSnippetLimit),
    overflow: occurrences.slice(withSnippetLimit),
  };
}

function riskPercentages(summary: ReportSummary): Record<Severity, number> {
  if (summary.total <= 0) {
    return { critical: 0, high: 0, medium: 0, low: 0 };
  }
  const scale = 100 / summary.total;
  return {
    critical: Math.round(summary.bySeverity.critical * scale),
    high: Math.round(summary.bySeverity.high * scale),
    medium: Math.round(summary.bySeverity.medium * scale),
    low: Math.round(summary.bySeverity.low * scale),
  };
}

function buildRiskMixConic(summary: ReportSummary): string {
  if (summary.total <= 0) {
    return "var(--low) 0% 100%";
  }

  const critical = (summary.bySeverity.critical / summary.total) * 100;
  const high = (summary.bySeverity.high / summary.total) * 100;
  const medium = (summary.bySeverity.medium / summary.total) * 100;
  const criticalEnd = critical;
  const highEnd = criticalEnd + high;
  const mediumEnd = highEnd + medium;

  return [
    `var(--critical) 0% ${criticalEnd.toFixed(2)}%`,
    `var(--high) ${criticalEnd.toFixed(2)}% ${highEnd.toFixed(2)}%`,
    `var(--medium) ${highEnd.toFixed(2)}% ${mediumEnd.toFixed(2)}%`,
    `var(--low) ${mediumEnd.toFixed(2)}% 100%`,
  ].join(", ");
}

function summarizeOccurrences(
  occurrences: ReportOccurrence[],
  limit: number,
): { shown: string[]; remaining: number } {
  const shown = occurrences.slice(0, limit).map((occurrence) => `${occurrence.file}:${occurrence.line}`);
  return {
    shown,
    remaining: Math.max(0, occurrences.length - shown.length),
  };
}

