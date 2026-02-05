import path from "node:path";
import type { Finding, RuleContext } from "./types.js";
import { RULES } from "./rules/index.js";
import { createScanProject } from "./project.js";
import { selectRules } from "./filters.js";

export interface ScanResult {
  findings: Finding[];
  scannedFiles: string[];
}

export function scanRepositoryDetailed(
  rootPath: string,
  options?: { rules?: string[] },
): ScanResult {
  const project = createScanProject(rootPath);
  const sourceFiles = project.getSourceFiles();

  const context: RuleContext = {
    project,
    sourceFiles,
    rootPath: path.resolve(rootPath),
  };

  const findings: Finding[] = [];
  const activeRules = selectRules(RULES, options?.rules);

  for (const rule of activeRules) {
    findings.push(...rule.run(context));
  }

  return {
    findings: dedupeFindings(findings),
    scannedFiles: sourceFiles.map((file) => file.getFilePath()),
  };
}

export function scanRepository(
  rootPath: string,
  options?: { rules?: string[] },
): Finding[] {
  return scanRepositoryDetailed(rootPath, options).findings;
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const unique: Finding[] = [];
  for (const finding of findings) {
    const fileKey = normalizeFileKey(finding.file);
    const key = [
      finding.rule_id,
      fileKey,
      finding.line,
      finding.summary,
    ].join("|");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(finding);
  }
  return unique;
}

function normalizeFileKey(filePath: string): string {
  const normalized = filePath.replace(/\\/g, "/").toLowerCase();
  return normalized.replace(/\.(ts|tsx|js|jsx)$/, "");
}
