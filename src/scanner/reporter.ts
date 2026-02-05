import type { Finding } from "./types.js";

export function formatReport(findings: Finding[], format: string): string {
  const normalized = format.trim().toLowerCase();
  if (normalized === "md" || normalized === "markdown") {
    return formatMarkdown(findings);
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
