import type { Finding } from "./types.js";

export function formatReport(findings: Finding[], format: string): string {
  const normalized = format.trim().toLowerCase();
  if (normalized === "md" || normalized === "markdown") {
    return formatMarkdown(findings);
  }
  if (normalized === "html") {
    return formatHtml(findings);
  }
  return JSON.stringify({ findings }, null, 2);
}

function formatMarkdown(findings: Finding[]): string {
  const lines: string[] = [];
  lines.push("# SecureAI-Scan Report");
  lines.push("");

  lines.push("## Summary");
  lines.push("");
  lines.push(`Total findings: ${findings.length}`);
  lines.push("");

  if (findings.length === 0) {
    lines.push("No findings.");
    lines.push("");
    return lines.join("\n");
  }

  lines.push("## Findings Table");
  lines.push("");
  lines.push("| ID | Severity | Confidence | File | Line | Summary |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const finding of findings) {
    const severityLabel = formatSeverityMarkdown(finding.severity);
    lines.push(
      `| ${finding.rule_id} | ${severityLabel} | ${finding.confidence.toFixed(2)} | ${finding.file} | ${finding.line} | ${finding.summary} |`,
    );
  }
  lines.push("");

  lines.push("## Details");
  lines.push("");
  for (const finding of findings) {
    lines.push(`### ${finding.rule_id}: ${finding.title}`);
    lines.push("");
    lines.push(`- Severity: ${formatSeverityMarkdown(finding.severity)}`);
    lines.push(`- File: ${finding.file}`);
    lines.push(`- Line: ${finding.line}`);
    lines.push(`- Confidence: ${finding.confidence.toFixed(2)}`);
    lines.push(`- Summary: ${finding.summary}`);
    lines.push("");
    lines.push(finding.description);
    lines.push("");
    lines.push(`Recommendation: ${finding.recommendation}`);
    lines.push("");
  }

  return lines.join("\n");
}

function formatHtml(findings: Finding[]): string {
  const summary = summarize(findings);
  const rows = findings
    .map((finding) => {
      return `
        <tr>
          <td class="id">${escapeHtml(finding.rule_id)}</td>
          <td class="severity ${finding.severity}">${severityLabel(finding.severity)}</td>
          <td class="confidence">${finding.confidence.toFixed(2)}</td>
          <td class="file">${escapeHtml(finding.file)}</td>
          <td class="line">${finding.line}</td>
          <td class="summary">${escapeHtml(finding.summary)}</td>
        </tr>
      `;
    })
    .join("");

  const detailBlocks = findings
    .map((finding) => {
      return `
        <section class="finding">
          <h3>${escapeHtml(finding.rule_id)}: ${escapeHtml(finding.title)}</h3>
          <div class="meta">
            <span class="severity ${finding.severity}">${severityLabel(finding.severity)}</span>
            <span class="file">${escapeHtml(finding.file)}:${finding.line}</span>
            <span class="confidence">Confidence ${finding.confidence.toFixed(2)}</span>
          </div>
          <p class="summary">${escapeHtml(finding.summary)}</p>
          <p class="description">${escapeHtml(finding.description)}</p>
          <p class="recommendation"><strong>Recommendation:</strong> ${escapeHtml(
            finding.recommendation,
          )}</p>
        </section>
      `;
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
        color-scheme: light;
        --bg: #f7f5f2;
        --card: #ffffff;
        --text: #1f2937;
        --muted: #6b7280;
        --border: #e5e7eb;
        --critical: #b91c1c;
        --high: #d97706;
        --medium: #ca8a04;
        --low: #16a34a;
        --accent: #0f172a;
      }
      body {
        margin: 0;
        font-family: "Space Grotesk", "Sora", "Inter", system-ui, sans-serif;
        background: var(--bg);
        color: var(--text);
      }
      header {
        padding: 32px 24px 12px;
      }
      h1 {
        margin: 0 0 8px;
        font-size: 28px;
        letter-spacing: -0.02em;
      }
      .summary {
        display: grid;
        gap: 12px;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        padding: 0 24px 24px;
      }
      .summary-card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 16px;
        box-shadow: 0 10px 20px rgba(15, 23, 42, 0.06);
      }
      .summary-card h2 {
        margin: 0 0 4px;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        color: var(--muted);
      }
      .summary-card .value {
        font-size: 22px;
        font-weight: 600;
      }
      .table-wrap {
        padding: 0 24px 24px;
      }
      table {
        width: 100%;
        border-collapse: collapse;
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        overflow: hidden;
      }
      th, td {
        text-align: left;
        padding: 12px 14px;
        border-bottom: 1px solid var(--border);
        font-size: 13px;
      }
      th {
        background: #f1f5f9;
        color: var(--muted);
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-size: 11px;
      }
      tr:last-child td {
        border-bottom: none;
      }
      .severity {
        font-weight: 600;
      }
      .critical { color: var(--critical); }
      .high { color: var(--high); }
      .medium { color: var(--medium); }
      .low { color: var(--low); }
      .finding {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 16px;
        margin: 0 24px 16px;
        box-shadow: 0 10px 20px rgba(15, 23, 42, 0.05);
      }
      .finding h3 {
        margin: 0 0 8px;
        font-size: 16px;
      }
      .finding .meta {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        color: var(--muted);
        font-size: 12px;
        margin-bottom: 8px;
      }
      .finding .summary {
        font-weight: 600;
        margin: 8px 0;
      }
      .finding .description,
      .finding .recommendation {
        margin: 6px 0;
        color: var(--text);
      }
      footer {
        padding: 16px 24px 32px;
        color: var(--muted);
        font-size: 12px;
      }
    </style>
  </head>
  <body>
    <header>
      <h1>SecureAI-Scan Report</h1>
      <p>Quick view of AI security findings in this repo.</p>
    </header>

    <section class="summary">
      <div class="summary-card">
        <h2>Total Findings</h2>
        <div class="value">${summary.total}</div>
      </div>
      <div class="summary-card">
        <h2>Critical</h2>
        <div class="value critical">${summary.critical}</div>
      </div>
      <div class="summary-card">
        <h2>High</h2>
        <div class="value high">${summary.high}</div>
      </div>
      <div class="summary-card">
        <h2>Medium</h2>
        <div class="value medium">${summary.medium}</div>
      </div>
      <div class="summary-card">
        <h2>Low</h2>
        <div class="value low">${summary.low}</div>
      </div>
    </section>

    <section class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Severity</th>
            <th>Confidence</th>
            <th>File</th>
            <th>Line</th>
            <th>Summary</th>
          </tr>
        </thead>
        <tbody>
          ${rows || `<tr><td colspan="6">No findings.</td></tr>`}
        </tbody>
      </table>
    </section>

    ${detailBlocks || `<section class="finding"><p>No findings.</p></section>`}

    <footer>
      Generated by SecureAI-Scan.
    </footer>
  </body>
</html>`;
}

function summarize(findings: Finding[]) {
  const summary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) {
    summary[finding.severity] += 1;
  }
  return summary;
}

function severityLabel(severity: Finding["severity"]): string {
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

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatSeverityMarkdown(severity: Finding["severity"]): string {
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
