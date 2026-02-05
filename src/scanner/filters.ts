import type { Finding, Rule, Severity } from "./types.js";

const SEVERITY_RANK: Record<Severity, number> = {
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function filterFindingsBySeverity(
  findings: Finding[],
  minSeverity?: Severity,
): Finding[] {
  if (!minSeverity) {
    return findings;
  }
  const minRank = SEVERITY_RANK[minSeverity];
  return findings.filter((finding) => SEVERITY_RANK[finding.severity] >= minRank);
}

export function selectRules(
  rules: Rule[],
  selected?: string[],
): Rule[] {
  if (!selected || selected.length === 0) {
    return rules;
  }
  return rules.filter((rule) => selected.includes(rule.id));
}
