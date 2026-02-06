import path from "node:path";
import type { Finding, RuleContext } from "./types.js";
import { RULES } from "./rules/index.js";
import { createScanProject } from "./project.js";
import { selectRules } from "./filters.js";
import type { SourceFile } from "ts-morph";

export interface ScanResult {
  findings: Finding[];
  ignoredFindings: IgnoredFinding[];
  scannedFiles: string[];
}

export interface IgnoredFinding {
  finding: Finding;
  reason: string;
  annotationLine: number;
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

  const deduped = dedupeFindings(findings);
  const { activeFindings, ignoredFindings } = applyIgnoreAnnotations(sourceFiles, deduped);

  return {
    findings: activeFindings,
    ignoredFindings,
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

interface IgnoreDirective {
  ruleId: string;
  reason: string;
  line: number;
  consumed: boolean;
}

function applyIgnoreAnnotations(
  sourceFiles: SourceFile[],
  findings: Finding[],
): { activeFindings: Finding[]; ignoredFindings: IgnoredFinding[] } {
  const directivesByFile = parseIgnoreDirectives(sourceFiles);
  const activeFindings: Finding[] = [];
  const ignoredFindings: IgnoredFinding[] = [];

  const sortedFindings = [...findings].sort((a, b) => {
    const fileCompare = normalizeFileKey(a.file).localeCompare(normalizeFileKey(b.file));
    if (fileCompare !== 0) {
      return fileCompare;
    }
    return a.line - b.line;
  });

  for (const finding of sortedFindings) {
    const fileKey = normalizeFileKey(finding.file);
    const directives = directivesByFile.get(fileKey) ?? [];
    const match = directives.find(
      (directive) =>
        !directive.consumed &&
        directive.ruleId === finding.rule_id &&
        directive.line < finding.line,
    );

    if (match) {
      match.consumed = true;
      ignoredFindings.push({
        finding,
        reason: match.reason,
        annotationLine: match.line,
      });
      continue;
    }

    activeFindings.push(finding);
  }

  return { activeFindings, ignoredFindings };
}

function parseIgnoreDirectives(sourceFiles: SourceFile[]): Map<string, IgnoreDirective[]> {
  const byFile = new Map<string, IgnoreDirective[]>();
  const pattern = /^\s*\/\/\s*secureai-ignore\s+([A-Za-z0-9_]+)\s*:\s*(.+)\s*$/;

  for (const sourceFile of sourceFiles) {
    const directives: IgnoreDirective[] = [];
    const lines = sourceFile.getFullText().split(/\r?\n/);

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const match = line.match(pattern);
      if (!match) {
        continue;
      }
      const reason = match[2].trim();
      if (reason.length === 0) {
        continue;
      }
      directives.push({
        ruleId: match[1].toUpperCase(),
        reason,
        line: index + 1,
        consumed: false,
      });
    }

    if (directives.length > 0) {
      byFile.set(normalizeFileKey(sourceFile.getFilePath()), directives);
    }
  }

  return byFile;
}
