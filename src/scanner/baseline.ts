import fs from "node:fs";
import path from "node:path";
import type { Finding, Severity } from "./types.js";

export interface BaselineEntry {
  rule_id: string;
  file: string;
  line: number;
  severity: Severity;
  confidence: number;
}

export interface BaselineFile {
  schema: "secureai-baseline/v1";
  createdAt: string;
  findings: BaselineEntry[];
}

export interface BaselineResult {
  created: boolean;
  findings: Finding[];
  newOrRegressedCount: number;
}

export function applyBaseline(filePath: string, findings: Finding[]): BaselineResult {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    writeBaseline(resolved, findings);
    return {
      created: true,
      findings,
      newOrRegressedCount: findings.length,
    };
  }

  const baseline = readBaseline(resolved);
  const baselineByKey = new Map<string, BaselineEntry>();
  for (const entry of baseline.findings) {
    baselineByKey.set(findingKey(entry.rule_id, entry.file, entry.line), entry);
  }

  const diff = findings.filter((finding) => {
    const key = findingKey(finding.rule_id, finding.file, finding.line);
    const previous = baselineByKey.get(key);
    if (!previous) {
      return true;
    }
    if (severityRank(finding.severity) > severityRank(previous.severity)) {
      return true;
    }
    return finding.confidence > previous.confidence + 0.000001;
  });

  return {
    created: false,
    findings: diff,
    newOrRegressedCount: diff.length,
  };
}

function writeBaseline(filePath: string, findings: Finding[]): void {
  const baseline: BaselineFile = {
    schema: "secureai-baseline/v1",
    createdAt: new Date().toISOString(),
    findings: findings
      .map((finding) => ({
        rule_id: finding.rule_id,
        file: finding.file,
        line: finding.line,
        severity: finding.severity,
        confidence: finding.confidence,
      }))
      .sort((a, b) => {
        const keyA = findingKey(a.rule_id, a.file, a.line);
        const keyB = findingKey(b.rule_id, b.file, b.line);
        return keyA.localeCompare(keyB);
      }),
  };

  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(baseline, null, 2), "utf-8");
}

function readBaseline(filePath: string): BaselineFile {
  const raw = fs.readFileSync(filePath, "utf-8");
  const parsed = JSON.parse(raw) as Partial<BaselineFile>;
  if (parsed.schema !== "secureai-baseline/v1" || !Array.isArray(parsed.findings)) {
    throw new Error(
      `Invalid baseline file "${filePath}". Expected schema "secureai-baseline/v1".`,
    );
  }
  return {
    schema: parsed.schema,
    createdAt: parsed.createdAt ?? "",
    findings: parsed.findings,
  };
}

function findingKey(ruleId: string, filePath: string, line: number): string {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return `${ruleId}|${normalized}|${line}`;
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
