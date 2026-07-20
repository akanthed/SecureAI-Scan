import fs from "node:fs";
import path from "node:path";
import type { Evidence, Finding, Severity, TraceStep } from "./types.js";
import { catalogFor } from "./catalog.js";

// ─────────────────────────────────────────────────────────────────────────────
// Report model
// ─────────────────────────────────────────────────────────────────────────────

export interface ReportMeta {
  tool: "SecureAI-Scan";
  version: string;
  scannedAt: string;
  filesScanned?: number;
  durationMs?: number;
}

export interface ReportSummary {
  total: number;
  bySeverity: Record<Severity, number>;
  byEvidence: Record<Evidence, number>;
  /** Findings hidden because they are heuristic tier (shown with --paranoid). */
  hiddenHeuristic?: number;
}

export interface ReportSnippetLine {
  lineNumber: number;
  text: string;
  highlight: boolean;
}

export interface ReportOccurrence {
  file: string;
  line: number;
  summary: string;
  evidence: Evidence;
  trace?: TraceStep[];
  snippet?: ReportSnippetLine[];
}

export interface ReportGroup {
  ruleId: string;
  title: string;
  severity: Severity;
  evidence: Evidence; // strongest across occurrences
  owasp?: string;
  owaspName?: string;
  asi?: string;
  asiName?: string;
  mcpTop10?: string;
  mcpTop10Name?: string;
  euAiAct?: string;
  impact?: string;
  shortFix?: string;
  recommendation: string;
  description: string;
  occurrences: ReportOccurrence[];
}

export interface ReportIgnoredFinding {
  ruleId: string;
  title: string;
  severity: Severity;
  file: string;
  line: number;
  reason: string;
  annotationLine: number;
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
  groups: ReportGroup[];
  ignoredFindings: ReportIgnoredFinding[];
}

export interface BuildReportOptions {
  rootPath?: string;
  ignoredFindings?: Array<{ finding: Finding; reason: string; annotationLine: number }>;
  baselineDiff?: ReportBaselineDiff;
  hiddenHeuristic?: number;
  filesScanned?: number;
  durationMs?: number;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];
const EVIDENCE_ORDER: Evidence[] = ["proven", "likely", "heuristic"];

function severityRank(s: Severity): number {
  return { critical: 4, high: 3, medium: 2, low: 1 }[s] ?? 0;
}
function evidenceRank(e: Evidence): number {
  return { proven: 3, likely: 2, heuristic: 1 }[e] ?? 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// buildReport
// ─────────────────────────────────────────────────────────────────────────────

export function buildReport(
  findings: Finding[],
  meta: ReportMeta,
  options?: BuildReportOptions,
): ReportModel {
  const snippets = new SnippetReader(options?.rootPath);

  const byRule = new Map<string, Finding[]>();
  for (const f of findings) {
    const list = byRule.get(f.rule_id) ?? [];
    list.push(f);
    byRule.set(f.rule_id, list);
  }

  const groups: ReportGroup[] = [];
  for (const [ruleId, list] of byRule.entries()) {
    const cat = catalogFor(ruleId);
    const first = list[0];
    const strongest = list.reduce<Evidence>(
      (acc, f) => (evidenceRank(f.evidence) > evidenceRank(acc) ? f.evidence : acc),
      "heuristic",
    );
    const maxSeverity = list.reduce<Severity>(
      (acc, f) => (severityRank(f.severity) > severityRank(acc) ? f.severity : acc),
      "low",
    );
    groups.push({
      ruleId,
      title: cat?.title ?? first.title,
      severity: maxSeverity,
      evidence: strongest,
      owasp: cat?.owasp,
      owaspName: cat?.owaspName,
      asi: cat?.asi,
      asiName: cat?.asiName,
      mcpTop10: cat?.mcpTop10,
      mcpTop10Name: cat?.mcpTop10Name,
      euAiAct: cat?.euAiAct,
      impact: cat?.impact,
      shortFix: cat?.shortFix,
      recommendation: first.recommendation,
      description: first.description,
      occurrences: [...list]
        .sort((a, b) => (a.file === b.file ? a.line - b.line : a.file.localeCompare(b.file)))
        .map((f) => ({
          file: f.file,
          line: f.line,
          summary: f.summary,
          evidence: f.evidence,
          trace: f.trace,
          snippet: snippets.read(f.file, f.line),
        })),
    });
  }

  groups.sort((a, b) => {
    const sev = severityRank(b.severity) - severityRank(a.severity);
    if (sev !== 0) return sev;
    const ev = evidenceRank(b.evidence) - evidenceRank(a.evidence);
    if (ev !== 0) return ev;
    return a.ruleId.localeCompare(b.ruleId);
  });

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  const byEvidence: Record<Evidence, number> = { proven: 0, likely: 0, heuristic: 0 };
  for (const f of findings) {
    bySeverity[f.severity] += 1;
    byEvidence[f.evidence] += 1;
  }

  return {
    meta: {
      ...meta,
      filesScanned: options?.filesScanned,
      durationMs: options?.durationMs,
    },
    summary: {
      total: findings.length,
      bySeverity,
      byEvidence,
      hiddenHeuristic: options?.hiddenHeuristic,
    },
    baselineDiff: options?.baselineDiff,
    groups,
    ignoredFindings: (options?.ignoredFindings ?? []).map((entry) => ({
      ruleId: entry.finding.rule_id,
      title: entry.finding.title,
      severity: entry.finding.severity,
      file: entry.finding.file,
      line: entry.finding.line,
      reason: entry.reason,
      annotationLine: entry.annotationLine,
    })),
  };
}

class SnippetReader {
  private rootPath?: string;
  private cache = new Map<string, string[] | undefined>();

  constructor(rootPath?: string) {
    this.rootPath = rootPath ? path.resolve(rootPath) : undefined;
  }

  read(findingFile: string, line: number): ReportSnippetLine[] | undefined {
    const lines = this.lines(findingFile);
    if (!lines || line <= 0 || line > lines.length) return undefined;
    const start = Math.max(1, line - 1);
    const end = Math.min(lines.length, line + 1);
    const out: ReportSnippetLine[] = [];
    for (let n = start; n <= end; n += 1) {
      out.push({ lineNumber: n, text: lines[n - 1], highlight: n === line });
    }
    return out;
  }

  private lines(findingFile: string): string[] | undefined {
    const resolved = path.isAbsolute(findingFile)
      ? findingFile
      : this.rootPath
        ? path.resolve(this.rootPath, findingFile)
        : path.resolve(findingFile);
    if (this.rootPath) {
      const normalized = path.normalize(resolved);
      if (normalized !== this.rootPath && !normalized.startsWith(this.rootPath + path.sep)) {
        return undefined;
      }
    }
    // Only fold case for the cache key on platforms with case-insensitive
    // filesystems — on Linux/macOS CI runners, two paths differing only by
    // case are distinct files, and lowercasing here would let one mask the
    // other's snippet content.
    const key = process.platform === "win32" ? resolved.toLowerCase() : resolved;
    if (this.cache.has(key)) return this.cache.get(key);
    try {
      const lines = fs.readFileSync(resolved, "utf-8").split(/\r?\n/);
      this.cache.set(key, lines);
      return lines;
    } catch {
      this.cache.set(key, undefined);
      return undefined;
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Format dispatch
// ─────────────────────────────────────────────────────────────────────────────

export type ReportFormat = "markdown" | "md" | "html" | "json" | "sarif";

export function formatReport(report: ReportModel, format: ReportFormat): string {
  const normalized = format.trim().toLowerCase();
  if (normalized === "md" || normalized === "markdown") return formatMarkdown(report);
  if (normalized === "html") return formatHtml(report);
  if (normalized === "sarif") return formatSarif(report);
  return JSON.stringify(report, null, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// Terminal
// ─────────────────────────────────────────────────────────────────────────────

const USE_COLOR = Boolean(process.stdout.isTTY) && process.env.NO_COLOR === undefined;

function ansi(code: string, text: string): string {
  return USE_COLOR ? `\x1b[${code}m${text}\x1b[0m` : text;
}

const tc = {
  bold: (t: string) => ansi("1", t),
  dim: (t: string) => ansi("2", t),
  red: (t: string) => ansi("91", t),
  orange: (t: string) => ansi("38;5;208", t),
  yellow: (t: string) => ansi("33", t),
  green: (t: string) => ansi("92", t),
  cyan: (t: string) => ansi("36", t),
  magenta: (t: string) => ansi("95", t),

  severity(severity: Severity, text: string): string {
    switch (severity) {
      case "critical": return tc.bold(tc.red(text));
      case "high": return tc.bold(tc.orange(text));
      case "medium": return tc.bold(tc.yellow(text));
      case "low": return tc.bold(tc.cyan(text));
    }
  },

  evidence(evidence: Evidence): string {
    switch (evidence) {
      case "proven": return tc.bold(tc.green("PROVEN"));
      case "likely": return tc.bold(tc.cyan("LIKELY"));
      case "heuristic": return tc.dim("HEURISTIC");
    }
  },
};

export function formatTerminalReport(report: ReportModel, limit = 10): string {
  const out: string[] = [];
  const { summary, meta } = report;
  const divider = tc.dim("─".repeat(64));

  const fileInfo = meta.filesScanned !== undefined ? ` · ${meta.filesScanned} files` : "";
  const timing = meta.durationMs !== undefined ? ` · ${(meta.durationMs / 1000).toFixed(1)}s` : "";
  out.push("");
  out.push(`  ${tc.bold("SecureAI-Scan")} ${tc.dim("v" + meta.version)}${tc.dim(fileInfo)}${tc.dim(timing)}`);
  out.push(`  ${divider}`);

  if (summary.total === 0) {
    out.push("");
    out.push(`  ${tc.bold(tc.green("✓"))} ${tc.green("No findings at the current evidence level.")}`);
    if (summary.hiddenHeuristic) {
      out.push(`  ${tc.dim(`${summary.hiddenHeuristic} heuristic finding(s) hidden — run with --paranoid to see them.`)}`);
    }
    out.push("");
    return out.join("\n");
  }

  // Summary line
  const sevParts = SEVERITY_ORDER.filter((s) => summary.bySeverity[s] > 0).map((s) =>
    tc.severity(s, `${summary.bySeverity[s]} ${s}`),
  );
  const evParts = EVIDENCE_ORDER.filter((e) => summary.byEvidence[e] > 0).map(
    (e) => `${summary.byEvidence[e]} ${e}`,
  );
  out.push("");
  out.push(`  ${tc.bold(String(summary.total))} finding(s)   ${sevParts.join(tc.dim(" · "))}`);
  out.push(`  ${tc.dim("evidence")}     ${tc.dim(evParts.join(" · "))}`);
  if (summary.hiddenHeuristic) {
    out.push(`  ${tc.dim(`+${summary.hiddenHeuristic} heuristic hidden (--paranoid to show)`)}`);
  }
  if (report.baselineDiff && !report.baselineDiff.created) {
    out.push(
      `  ${tc.dim(`baseline     ${report.baselineDiff.newOrRegressedCount} new · ${report.baselineDiff.unchangedCount} unchanged`)}`,
    );
  }
  if (report.ignoredFindings.length > 0) {
    out.push(`  ${tc.dim(`${report.ignoredFindings.length} suppressed via secureai-ignore`)}`);
  }

  const shown = report.groups.slice(0, Math.max(1, limit));
  for (const group of shown) {
    const tag = group.owasp ? `  ${tc.magenta(group.owasp)}` : "";
    const extraFrameworks = [
      group.asi ? `${group.asi} ${group.asiName ?? ""}`.trim() : "",
      group.mcpTop10 ? `MCP-Top10 ${group.mcpTop10} ${group.mcpTop10Name ?? ""}`.trim() : "",
    ]
      .filter(Boolean)
      .join(" · ");
    out.push("");
    out.push(`  ${divider}`);
    out.push(
      `  ${tc.severity(group.severity, "▌ " + group.severity.toUpperCase())}  ${tc.bold(group.ruleId)}  ${tc.bold(group.title)}`,
    );
    out.push(
      `    ${tc.evidence(group.evidence)}${tag}${group.owaspName ? tc.dim(" " + group.owaspName) : ""}${extraFrameworks ? tc.dim(" · " + extraFrameworks) : ""}`,
    );

    const first = group.occurrences[0];
    if (first?.trace && first.trace.length > 0) {
      out.push("");
      for (const step of first.trace) {
        const label = step.kind.padEnd(6, " ");
        const loc = `${step.file}:${step.line}`;
        out.push(`    ${tc.dim(label)} ${tc.cyan(loc)}  ${step.note}`);
      }
    } else if (first) {
      out.push("");
      out.push(`    ${tc.dim("at")}     ${tc.cyan(`${first.file}:${first.line}`)}  ${tc.dim(first.summary)}`);
    }

    if (first?.snippet) {
      const hit = first.snippet.find((s) => s.highlight);
      if (hit) {
        const text = hit.text.length > 96 ? hit.text.slice(0, 93) + "…" : hit.text;
        out.push(`    ${tc.dim(String(hit.lineNumber).padStart(5) + " │")} ${text.trim()}`);
      }
    }

    if (group.occurrences.length > 1) {
      const extras = group.occurrences.slice(1, 4).map((o) => `${o.file}:${o.line}`);
      const more = group.occurrences.length - 1 - extras.length;
      out.push(`    ${tc.dim(`also   ${extras.join(", ")}${more > 0 ? ` (+${more} more)` : ""}`)}`);
    }

    const fix = group.shortFix ?? group.recommendation;
    out.push("");
    out.push(`    ${tc.green("fix")}    ${fix}`);
  }

  out.push("");
  out.push(`  ${divider}`);
  if (report.groups.length > shown.length) {
    out.push(
      `  ${tc.dim(`${report.groups.length - shown.length} more rule group(s) — increase --limit or use --output report.html`)}`,
    );
  }
  const topRule = shown[0]?.ruleId;
  out.push(
    `  ${tc.dim("next")}   ${topRule ? `secureai-scan explain ${topRule}` : ""}${topRule ? tc.dim("  ·  ") : ""}--output report.sarif ${tc.dim("→ GitHub code scanning")}`,
  );
  out.push("");

  return out.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// Markdown
// ─────────────────────────────────────────────────────────────────────────────

function formatMarkdown(report: ReportModel): string {
  const lines: string[] = [];
  const { summary } = report;

  lines.push("# SecureAI-Scan Report");
  lines.push("");
  lines.push(`Scanned ${report.meta.scannedAt} · v${report.meta.version}`);
  lines.push("");
  lines.push("| Total | Critical | High | Medium | Low | Proven | Likely | Heuristic |");
  lines.push("|------:|---------:|-----:|-------:|----:|-------:|-------:|----------:|");
  lines.push(
    `| ${summary.total} | ${summary.bySeverity.critical} | ${summary.bySeverity.high} | ${summary.bySeverity.medium} | ${summary.bySeverity.low} | ${summary.byEvidence.proven} | ${summary.byEvidence.likely} | ${summary.byEvidence.heuristic} |`,
  );
  lines.push("");

  if (report.baselineDiff) {
    lines.push(
      report.baselineDiff.created
        ? `Baseline created this run (${report.baselineDiff.currentCount} findings captured).`
        : `Baseline diff: **${report.baselineDiff.newOrRegressedCount} new/regressed**, ${report.baselineDiff.unchangedCount} unchanged.`,
    );
    lines.push("");
  }

  if (report.groups.length === 0) {
    lines.push("No findings at the current evidence level.");
    lines.push("");
  }

  for (const group of report.groups) {
    const tags = [
      group.evidence.toUpperCase(),
      group.owasp ? `OWASP ${group.owasp} ${group.owaspName}` : "",
      group.asi ? `OWASP ${group.asi} ${group.asiName}` : "",
      group.mcpTop10 ? `OWASP MCP Top 10 ${group.mcpTop10} ${group.mcpTop10Name}` : "",
      group.euAiAct ?? "",
    ]
      .filter(Boolean)
      .join(" · ");
    lines.push(`## ${group.severity.toUpperCase()} — ${group.ruleId}: ${group.title}`);
    lines.push("");
    lines.push(`*${tags}*`);
    lines.push("");
    if (group.impact) lines.push(`**Impact:** ${group.impact}`);
    lines.push(`**Why flagged:** ${group.description}`);
    lines.push(`**Fix:** ${group.recommendation}`);
    lines.push("");
    for (const occ of group.occurrences) {
      lines.push(`- \`${occ.file}:${occ.line}\` — ${occ.summary}`);
      if (occ.trace) {
        for (const step of occ.trace) {
          lines.push(`  - ${step.kind}: \`${step.file}:${step.line}\` ${step.note}`);
        }
      }
      if (occ.snippet) {
        lines.push("");
        lines.push("  ```");
        for (const s of occ.snippet) {
          lines.push(`  ${s.highlight ? ">" : " "} ${String(s.lineNumber).padStart(4)} | ${s.text}`);
        }
        lines.push("  ```");
      }
    }
    lines.push("");
  }

  if (report.ignoredFindings.length > 0) {
    lines.push("## Suppressed findings");
    lines.push("");
    for (const ig of report.ignoredFindings) {
      lines.push(`- ${ig.ruleId} \`${ig.file}:${ig.line}\` — ${ig.reason} (annotation line ${ig.annotationLine})`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ─────────────────────────────────────────────────────────────────────────────
// SARIF 2.1.0 — GitHub code scanning
// ─────────────────────────────────────────────────────────────────────────────

function sarifLevel(severity: Severity): string {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function sarifSecuritySeverity(severity: Severity): string {
  // GitHub maps security-severity: 9+ critical, 7–8.9 high, 4–6.9 medium, <4 low
  switch (severity) {
    case "critical": return "9.5";
    case "high": return "8.0";
    case "medium": return "5.0";
    case "low": return "3.0";
  }
}

export function formatSarif(report: ReportModel): string {
  const ruleIds = [...new Set(report.groups.map((g) => g.ruleId))];
  const rules = ruleIds.map((id) => {
    const cat = catalogFor(id);
    const group = report.groups.find((g) => g.ruleId === id)!;
    return {
      id,
      name: id,
      shortDescription: { text: cat?.title ?? group.title },
      fullDescription: { text: cat?.impact ?? group.description },
      help: {
        text: `${group.recommendation}\n\nRun: secureai-scan explain ${id}`,
        markdown: `**Fix:** ${group.recommendation}\n\n\`secureai-scan explain ${id}\``,
      },
      helpUri: "https://github.com/akanthed/SecureAI-Scan#rules",
      defaultConfiguration: { level: sarifLevel(cat?.severity ?? group.severity) },
      properties: {
        "security-severity": sarifSecuritySeverity(cat?.severity ?? group.severity),
        tags: [
          "security",
          "ai",
          cat?.owasp ? `owasp-llm-top10/${cat.owasp.toLowerCase()}` : "",
          cat?.asi ? `owasp-asi-2026/${cat.asi.toLowerCase()}` : "",
          cat?.mcpTop10 ? `owasp-mcp-top10/${cat.mcpTop10.toLowerCase()}` : "",
        ].filter(Boolean),
      },
    };
  });

  const results = report.groups.flatMap((group) =>
    group.occurrences.map((occ) => {
      const traceText = occ.trace
        ? "\n" + occ.trace.map((s) => `${s.kind}: ${s.file}:${s.line} — ${s.note}`).join("\n")
        : "";
      return {
        ruleId: group.ruleId,
        level: sarifLevel(group.severity),
        message: {
          text: `${occ.summary}${traceText}\n\nFix: ${group.shortFix ?? group.recommendation}`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: { uri: occ.file.replace(/\\/g, "/"), uriBaseId: "%SRCROOT%" },
              region: { startLine: Math.max(1, occ.line) },
            },
          },
        ],
        partialFingerprints: {
          secureaiScanFingerprint: `${group.ruleId}:${occ.file.replace(/\\/g, "/")}:${occ.line}`,
        },
        properties: { evidence: occ.evidence },
      };
    }),
  );

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "SecureAI-Scan",
            version: report.meta.version,
            informationUri: "https://github.com/akanthed/SecureAI-Scan",
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

// ─────────────────────────────────────────────────────────────────────────────
// HTML — clean, print-friendly, light/dark aware
// ─────────────────────────────────────────────────────────────────────────────

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatHtml(report: ReportModel): string {
  const { summary } = report;

  const chips = [
    `<span class="chip">Total <strong>${summary.total}</strong></span>`,
    `<span class="chip sev-critical">Critical <strong>${summary.bySeverity.critical}</strong></span>`,
    `<span class="chip sev-high">High <strong>${summary.bySeverity.high}</strong></span>`,
    `<span class="chip sev-medium">Medium <strong>${summary.bySeverity.medium}</strong></span>`,
    `<span class="chip sev-low">Low <strong>${summary.bySeverity.low}</strong></span>`,
    `<span class="chip">Proven <strong>${summary.byEvidence.proven}</strong></span>`,
    `<span class="chip">Likely <strong>${summary.byEvidence.likely}</strong></span>`,
  ].join("");

  const groupsHtml = report.groups
    .map((group) => {
      const occs = group.occurrences
        .map((occ) => {
          const trace = occ.trace
            ? `<div class="trace">${occ.trace
                .map(
                  (s) =>
                    `<div class="trace-step"><span class="trace-kind ${s.kind}">${s.kind}</span><code>${escapeHtml(
                      `${s.file}:${s.line}`,
                    )}</code><span>${escapeHtml(s.note)}</span></div>`,
                )
                .join("")}</div>`
            : "";
          const snippet = occ.snippet
            ? `<pre class="snippet">${occ.snippet
                .map(
                  (l) =>
                    `<div class="code-line${l.highlight ? " hit" : ""}"><span class="num">${l.lineNumber}</span><span>${escapeHtml(l.text)}</span></div>`,
                )
                .join("")}</pre>`
            : "";
          return `<li><code>${escapeHtml(occ.file)}:${occ.line}</code> — ${escapeHtml(occ.summary)}${trace}${snippet}</li>`;
        })
        .join("");

      const tags = [
        `<span class="tag ev-${group.evidence}">${group.evidence}</span>`,
        group.owasp ? `<span class="tag">OWASP ${group.owasp} · ${escapeHtml(group.owaspName ?? "")}</span>` : "",
        group.asi ? `<span class="tag">OWASP ${group.asi} · ${escapeHtml(group.asiName ?? "")}</span>` : "",
        group.mcpTop10 ? `<span class="tag">OWASP MCP Top 10 ${group.mcpTop10} · ${escapeHtml(group.mcpTop10Name ?? "")}</span>` : "",
        group.euAiAct ? `<span class="tag">EU AI Act ${escapeHtml(group.euAiAct)}</span>` : "",
      ].join("");

      return `<section class="finding sev-${group.severity}">
        <header>
          <span class="sev">${group.severity.toUpperCase()}</span>
          <h2>${escapeHtml(group.ruleId)} — ${escapeHtml(group.title)}</h2>
        </header>
        <div class="tags">${tags}</div>
        ${group.impact ? `<p class="impact">${escapeHtml(group.impact)}</p>` : ""}
        <p>${escapeHtml(group.description)}</p>
        <p class="fix"><strong>Fix:</strong> ${escapeHtml(group.recommendation)}</p>
        <ul class="occurrences">${occs}</ul>
      </section>`;
    })
    .join("\n");

  const ignoredHtml =
    report.ignoredFindings.length > 0
      ? `<section class="finding muted"><header><h2>Suppressed findings</h2></header><ul>${report.ignoredFindings
          .map(
            (ig) =>
              `<li>${escapeHtml(ig.ruleId)} <code>${escapeHtml(ig.file)}:${ig.line}</code> — ${escapeHtml(ig.reason)}</li>`,
          )
          .join("")}</ul></section>`
      : "";

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SecureAI-Scan Report</title>
<style>
  :root {
    --bg: #f6f8fa; --card: #ffffff; --text: #1f2328; --muted: #59636e;
    --border: #d1d9e0; --critical: #a40e26; --high: #bc4c00; --medium: #9a6700;
    --low: #1a7f37; --accent: #0969da;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #0d1117; --card: #161b22; --text: #e6edf3; --muted: #8d96a0;
      --border: #30363d; --critical: #ff7b72; --high: #f0883e; --medium: #d29922;
      --low: #3fb950; --accent: #58a6ff;
    }
  }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  .meta { color: var(--muted); font-size: 13px; margin-bottom: 20px; }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 28px; }
  .chip { border: 1px solid var(--border); background: var(--card); border-radius: 999px;
    padding: 4px 12px; font-size: 13px; color: var(--muted); }
  .chip strong { color: var(--text); margin-left: 4px; }
  .chip.sev-critical strong { color: var(--critical); }
  .chip.sev-high strong { color: var(--high); }
  .chip.sev-medium strong { color: var(--medium); }
  .chip.sev-low strong { color: var(--low); }
  .finding { background: var(--card); border: 1px solid var(--border);
    border-left-width: 4px; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  .finding.sev-critical { border-left-color: var(--critical); }
  .finding.sev-high { border-left-color: var(--high); }
  .finding.sev-medium { border-left-color: var(--medium); }
  .finding.sev-low { border-left-color: var(--low); }
  .finding header { display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; }
  .finding h2 { font-size: 17px; margin: 0; }
  .sev { font-size: 11px; font-weight: 700; letter-spacing: 0.06em; }
  .sev-critical .sev { color: var(--critical); }
  .sev-high .sev { color: var(--high); }
  .sev-medium .sev { color: var(--medium); }
  .sev-low .sev { color: var(--low); }
  .tags { display: flex; gap: 6px; flex-wrap: wrap; margin: 8px 0 4px; }
  .tag { font-size: 11px; border: 1px solid var(--border); border-radius: 999px;
    padding: 1px 9px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.04em; }
  .tag.ev-proven { color: var(--low); border-color: var(--low); }
  .tag.ev-likely { color: var(--accent); border-color: var(--accent); }
  .impact { color: var(--muted); font-style: italic; margin: 8px 0 4px; }
  .fix { background: color-mix(in srgb, var(--low) 8%, transparent);
    border: 1px solid color-mix(in srgb, var(--low) 30%, transparent);
    border-radius: 6px; padding: 8px 12px; }
  .occurrences { padding-left: 20px; }
  .occurrences li { margin-bottom: 12px; }
  code { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 13px;
    background: color-mix(in srgb, var(--border) 40%, transparent); border-radius: 4px; padding: 1px 5px; }
  .trace { margin: 8px 0; border-left: 2px solid var(--border); padding-left: 12px; }
  .trace-step { display: flex; gap: 10px; align-items: baseline; font-size: 13px; margin: 2px 0; }
  .trace-kind { width: 52px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; color: var(--muted); }
  .trace-kind.source { color: var(--high); }
  .trace-kind.sink { color: var(--critical); }
  .snippet { background: color-mix(in srgb, var(--border) 25%, transparent); border: 1px solid var(--border);
    border-radius: 6px; padding: 8px 0; overflow-x: auto; margin: 8px 0 0; }
  .code-line { display: grid; grid-template-columns: 48px 1fr; gap: 10px; padding: 0 12px;
    font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; white-space: pre; }
  .code-line .num { color: var(--muted); text-align: right; user-select: none; }
  .code-line.hit { background: color-mix(in srgb, var(--medium) 14%, transparent); }
  .muted { color: var(--muted); }
  .empty { text-align: center; padding: 48px 0; color: var(--low); font-size: 17px; }
  @media print { body { background: #fff; } .finding { break-inside: avoid; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>SecureAI-Scan Report</h1>
  <div class="meta">Scanned ${escapeHtml(report.meta.scannedAt)} · v${escapeHtml(report.meta.version)}${
    summary.hiddenHeuristic ? ` · ${summary.hiddenHeuristic} heuristic finding(s) hidden (--paranoid to include)` : ""
  }</div>
  <div class="chips">${chips}</div>
  ${report.groups.length === 0 ? `<div class="empty">✓ No findings at the current evidence level.</div>` : groupsHtml}
  ${ignoredHtml}
</div>
</body>
</html>`;
}
