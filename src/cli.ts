import { Command, InvalidArgumentError } from "commander";
import { scanRepositoryDetailed, type IgnoredFinding } from "./scanner/scan.js";
import {
  buildReport,
  formatReport,
  formatTerminalReport,
  type ReportBaselineDiff,
  type ReportModel,
} from "./scanner/reporter.js";
import type { Severity, Finding } from "./scanner/types.js";
import { filterFindingsBySeverity } from "./scanner/filters.js";
import { AVAILABLE_RULE_IDS } from "./scanner/rules/index.js";
import { StaticExplainer } from "./scanner/explainer.js";
import { applyBaseline } from "./scanner/baseline.js";
import { evaluatePromptRisk } from "./scanner/prompt-risk.js";
import { scanDependencyFilesForRisks } from "./scanner/dependency-guard.js";
import { loadPolicy, writeDefaultPolicy, writeGithubWorkflow } from "./scanner/policy.js";
import { generateThreatModel } from "./scanner/threat-model.js";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const ALLOWED_SEVERITIES = ["low", "medium", "high", "critical"] as const;

// ─── Helpers ────────────────────────────────────────────────────────────────

function parseSeverity(value: string): Severity {
  const normalized = value.trim().toLowerCase();
  if (ALLOWED_SEVERITIES.includes(normalized as Severity)) {
    return normalized as Severity;
  }
  throw new InvalidArgumentError(
    `Invalid --severity "${value}". Expected one of: ${ALLOWED_SEVERITIES.join(", ")}.`,
  );
}

function parseRules(value: string): string[] {
  const rules = value
    .split(",")
    .map((rule) => rule.trim().toUpperCase())
    .filter((rule) => rule.length > 0);

  if (rules.length === 0) {
    throw new InvalidArgumentError(
      "Invalid --rules value. Provide a comma-separated list of rule IDs.",
    );
  }

  const invalid = rules.filter((rule) => !AVAILABLE_RULE_IDS.includes(rule));
  if (invalid.length > 0) {
    throw new InvalidArgumentError(
      `Unknown rule ID(s): ${invalid.join(", ")}. Available rules: ${AVAILABLE_RULE_IDS.join(", ")}.`,
    );
  }

  return rules;
}

function parseLimit(value: string): number {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new InvalidArgumentError(`Invalid --limit "${value}". Expected a non-negative number.`);
  }
  return parsed;
}

function parseConfidence(value: string): number {
  const parsed = Number.parseFloat(value);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 1) {
    throw new InvalidArgumentError(`Invalid --min-confidence "${value}". Expected a number between 0 and 1.`);
  }
  return parsed;
}

// ─── CLI entry ───────────────────────────────────────────────────────────────

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();

  program
    .name("secureai-scan")
    .description("Repo-native AI security scanner — finds LLM, MCP, and RAG vulnerabilities")
    .version("0.2.0")
    .addHelpText(
      "after",
      [
        "",
        "Quick start:",
        "  secureai-scan init                   Set up policy + CI in 30 seconds",
        "  secureai-scan scan .                 Scan current repo",
        "  secureai-scan scan . --output r.html Save a shareable HTML report",
        "  secureai-scan threat-model .         Generate THREAT_MODEL.md",
        "  secureai-scan explain AI001          Show fix guide for a rule",
        "  secureai-scan prompt \"<text>\"        Evaluate raw prompt text",
        "",
        "Ignore a specific finding in code:",
        "  // secureai-ignore AI001: reviewed, sanitized via allowlist",
        "",
        `Rules: ${AVAILABLE_RULE_IDS.join(", ")}`,
      ].join("\n"),
    );

  // ── scan ─────────────────────────────────────────────────────────────────
  program
    .command("scan")
    .argument("<path>", "Path to the repository to scan")
    .option("-s, --severity <level>", "Minimum severity: low | medium | high | critical", parseSeverity)
    .option("-r, --rules <list>", "Comma-separated rule IDs to run", parseRules)
    .option("--only-ai", "Run only AI/LLM rules (AI001–AI012)")
    .option("--only-mcp", "Run only MCP rules (MCP001–MCP003)")
    .option("--only-vec", "Run only Vector/RAG rules (VEC001–VEC003)")
    .option("--limit <number>", "Limit number of findings shown in terminal", parseLimit)
    .option("--output <file>", "Save a full report as .html, .md, or .json")
    .option("--baseline <file>", "Track only new/changed issues using a baseline file")
    .option("--policy <file>", "Path to a .secureai-policy.json file (auto-detected if omitted)")
    .option("--min-confidence <0-1>", "Hide findings below this confidence score (default: 0.4)", parseConfidence)
    .option("--check-dependencies", "Scan package.json and requirements.txt for suspicious packages")
    .option("--debug", "Show scanned files and rule metadata")
    .addHelpText(
      "after",
      [
        "",
        "Ignore annotations:",
        "  // secureai-ignore <RULE_ID>: <reason>",
        "  Suppresses the next matching finding and records it under Ignored Findings.",
      ].join("\n"),
    )
    .action(
      async (
        targetPath: string,
        options: {
          severity?: Severity;
          rules?: string[];
          onlyAi?: boolean;
          onlyMcp?: boolean;
          onlyVec?: boolean;
          limit?: number;
          output?: string;
          baseline?: string;
          policy?: string;
          minConfidence?: number;
          checkDependencies?: boolean;
          debug?: boolean;
        },
      ) => {
        // Load policy (file arg > auto-detect in rootPath)
        let policyPath = options.policy;
        const policyResult = policyPath
          ? loadPolicy(path.dirname(policyPath))
          : loadPolicy(targetPath);

        if (policyResult) {
          process.stdout.write(`Policy loaded: ${policyResult.policyPath}\n`);
        }

        const activePolicy = policyResult?.policy ?? {};

        // Rule selection: CLI args override policy
        const selectedRules = resolveRuleSelection(
          options.rules ?? (activePolicy.onlyRules?.length ? activePolicy.onlyRules : undefined),
          options.onlyAi ?? false,
          options.onlyMcp ?? false,
          options.onlyVec ?? false,
        );

        const previousState = readScanState(targetPath);
        const scanResult = scanRepositoryDetailed(targetPath, { rules: selectedRules });
        const findings: Finding[] = [...scanResult.findings];

        if (options.checkDependencies) {
          const depFindings = await scanDependencyFilesForRisks({ rootPath: targetPath });
          findings.push(...depFindings);
        }

        // Confidence filter: CLI > policy > default 0.4
        const minConfidence = options.minConfidence ?? activePolicy.minConfidence ?? 0.4;
        const confidenceFiltered = findings.filter((f) => f.confidence >= minConfidence);

        // Severity filter: CLI > policy
        const minSeverity = options.severity ?? activePolicy.minSeverity;
        const filtered = filterFindingsBySeverity(confidenceFiltered, minSeverity);
        const filteredIgnored = filterIgnoredBySeverity(scanResult.ignoredFindings, minSeverity);

        let outputFindings = filtered;
        let baselineDiff: ReportBaselineDiff | undefined;

        if (options.baseline) {
          const baseline = applyBaseline(options.baseline, filtered);
          baselineDiff = {
            created: baseline.created,
            baselinePath: options.baseline,
            baselineCount: baseline.baselineCount,
            currentCount: baseline.currentCount,
            newOrRegressedCount: baseline.newOrRegressedCount,
            unchangedCount: Math.max(0, baseline.currentCount - baseline.newOrRegressedCount),
          };
          if (baseline.created) {
            process.stdout.write(
              "Baseline created. Future runs will show only new or changed issues.\n\n",
            );
          } else {
            outputFindings = baseline.findings;
            process.stdout.write(
              `New issues since baseline: ${baseline.newOrRegressedCount} (baseline: ${baseline.baselineCount}, current: ${baseline.currentCount})\n\n`,
            );
          }
        }

        const report = buildReport(
          outputFindings,
          {
            tool: "SecureAI-Scan",
            version: readPackageVersion(),
            scannedAt: new Date().toISOString(),
          },
          {
            rootPath: targetPath,
            ignoredFindings: filteredIgnored,
            baselineDiff,
          },
        );

        if (options.output) {
          writeFullReport(report, options.output);
        }

        const terminal = formatTerminalReport(report, options.limit ?? 3);
        process.stdout.write(`${terminal}\n`);

        // Hidden-by-confidence hint
        const hiddenCount = findings.length - confidenceFiltered.length;
        if (hiddenCount > 0) {
          process.stdout.write(
            `Note: ${hiddenCount} finding(s) hidden (confidence < ${minConfidence}). Lower --min-confidence to see them.\n`,
          );
        }

        maybePrintContextualHints(report, options.baseline, options.output, previousState, policyResult !== undefined);
        persistScanRun(targetPath, Boolean(options.baseline), previousState);

        // Policy: fail the process on severity threshold
        const failSeverity = activePolicy.failOnSeverity;
        if (failSeverity) {
          const failFindings = outputFindings.filter(
            (f) => severityValue(f.severity) >= severityValue(failSeverity),
          );
          if (failFindings.length > 0) {
            process.stderr.write(
              `\nPolicy violation: ${failFindings.length} finding(s) at or above "${failSeverity}" severity. Exiting with code 1.\n`,
            );
            process.exit(1);
          }
        }

        if (options.debug) {
          const files = scanResult.scannedFiles;
          process.stderr.write(
            `\n[debug] Scanned: ${files.length} files | Rules: ${selectedRules?.join(", ") ?? "all"} | minConfidence: ${minConfidence}\n`,
          );
          const preview = files.slice(0, 20);
          for (const f of preview) process.stderr.write(`  ${f}\n`);
          if (files.length > preview.length)
            process.stderr.write(`  ...and ${files.length - preview.length} more\n`);
        }
      },
    );

  // ── explain ──────────────────────────────────────────────────────────────
  program
    .command("explain")
    .argument("<rule_id>", "Rule ID to explain (e.g. AI001, MCP002, VEC003)")
    .description("Show why a rule exists, how it's exploited, and a concrete fix example")
    .action((ruleId: string) => {
      const normalized = ruleId.trim().toUpperCase();
      if (!AVAILABLE_RULE_IDS.includes(normalized)) {
        throw new InvalidArgumentError(
          `Unknown rule ID "${ruleId}". Available: ${AVAILABLE_RULE_IDS.join(", ")}.`,
        );
      }
      const explainer = new StaticExplainer();
      const explanation = explainer.explain({
        rule_id: normalized,
        title: normalized,
        severity: "medium",
        file: "",
        line: 0,
        summary: "",
        description: "",
        recommendation: "",
        confidence: 0,
      });

      process.stdout.write(`\n# ${normalized} — ${explanation.summary}\n\n`);
      process.stdout.write(`Why this is dangerous\n${"─".repeat(40)}\n${explanation.whyRisky}\n\n`);
      process.stdout.write(`How attackers exploit it\n${"─".repeat(40)}\n${explanation.howExploited}\n\n`);
      process.stdout.write(`How to fix it\n${"─".repeat(40)}\n${explanation.howToFix}\n\n`);
      process.stdout.write("Code example\n" + "─".repeat(40) + "\n");
      process.stdout.write("```ts\n");
      process.stdout.write(`${explanation.codeExample}\n`);
      process.stdout.write("```\n\n");
    });

  // ── prompt ────────────────────────────────────────────────────────────────
  program
    .command("prompt")
    .argument("<promptText...>", "Raw prompt text to evaluate for injection risk")
    .description("Evaluate prompt text for instruction-override and injection patterns")
    .action((promptText: string[]) => {
      const input = promptText.join(" ").trim();
      const result = evaluatePromptRisk(input);
      process.stdout.write("\nPrompt Risk Evaluator\n");
      process.stdout.write("─".repeat(40) + "\n");
      process.stdout.write(`Risk level:  ${result.level}\n`);
      process.stdout.write("Reasons:\n");
      for (const reason of result.reasons) process.stdout.write(`  • ${reason}\n`);
      process.stdout.write("Suggestions:\n");
      for (const suggestion of result.suggestions) process.stdout.write(`  • ${suggestion}\n`);
      process.stdout.write("\n");
    });

  // ── threat-model ─────────────────────────────────────────────────────────
  program
    .command("threat-model")
    .argument("<path>", "Path to the repository to analyse")
    .option("--output <file>", "Write threat model to file (default: THREAT_MODEL.md)")
    .option("--severity <level>", "Minimum severity to include", parseSeverity)
    .description("Generate a THREAT_MODEL.md from the repository's AI/LLM security posture")
    .action(async (targetPath: string, options: { output?: string; severity?: Severity }) => {
      process.stdout.write("Scanning for threat model generation...\n");
      const scanResult = scanRepositoryDetailed(targetPath);
      const findings = filterFindingsBySeverity(scanResult.findings, options.severity);

      const version = readPackageVersion();
      const content = generateThreatModel(findings, {
        scannedAt: new Date().toISOString(),
        version,
        rootPath: path.resolve(targetPath),
      });

      const outPath = path.resolve(options.output ?? path.join(targetPath, "THREAT_MODEL.md"));
      fs.writeFileSync(outPath, content, "utf-8");
      process.stdout.write(`Threat model written to: ${outPath}\n`);
      process.stdout.write(`Findings included: ${findings.length}\n`);
      process.stdout.write("\nNext steps:\n");
      process.stdout.write("  1. Review the attack scenarios with your security team\n");
      process.stdout.write("  2. Prioritise fixes from the Remediation Priority section\n");
      process.stdout.write("  3. Use `secureai-scan explain <RULE_ID>` for code-level guidance\n\n");
    });

  // ── init ─────────────────────────────────────────────────────────────────
  program
    .command("init")
    .argument("[path]", "Repository root to initialise (default: current directory)", ".")
    .option("--no-ci", "Skip GitHub Actions workflow creation")
    .description("Set up SecureAI-Scan: creates a policy file and optional CI workflow")
    .action((targetPath: string, options: { ci: boolean }) => {
      const resolved = path.resolve(targetPath);
      process.stdout.write("\nSecureAI-Scan Setup\n");
      process.stdout.write("─".repeat(40) + "\n\n");

      // Policy file
      const policyPath = writeDefaultPolicy(resolved);
      process.stdout.write(`✓ Policy file created: ${policyPath}\n`);
      process.stdout.write("  Edit it to tune severity thresholds and rule selection.\n\n");

      // GitHub Actions
      if (options.ci) {
        try {
          const workflowPath = writeGithubWorkflow(resolved);
          process.stdout.write(`✓ CI workflow created: ${workflowPath}\n\n`);
        } catch {
          process.stdout.write("  (Skipped CI workflow — could not write .github/workflows/)\n\n");
        }
      }

      // Baseline
      process.stdout.write("Your 4-step security journey:\n\n");
      process.stdout.write("  Step 1 — Scan your repo now:\n");
      process.stdout.write("    secureai-scan scan . --policy .secureai-policy.json\n\n");
      process.stdout.write("  Step 2 — Create a baseline (focus only on new issues in future):\n");
      process.stdout.write("    secureai-scan scan . --baseline .secureai-baseline.json\n\n");
      process.stdout.write("  Step 3 — Understand any finding:\n");
      process.stdout.write("    secureai-scan explain <RULE_ID>   e.g. secureai-scan explain AI001\n\n");
      process.stdout.write("  Step 4 — Generate a threat model for security review:\n");
      process.stdout.write("    secureai-scan threat-model .\n\n");
      process.stdout.write("  Bonus — Suppress a known-safe finding in code:\n");
      process.stdout.write("    // secureai-ignore AI001: sanitized via DOMPurify\n\n");

      process.stdout.write("─".repeat(40) + "\n");
      process.stdout.write("Docs: https://github.com/akanthed/SecureAI-Scan\n\n");
    });

  await program.parseAsync(argv);
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function resolveRuleSelection(
  rules: string[] | undefined,
  onlyAi: boolean,
  onlyMcp: boolean,
  onlyVec: boolean,
): string[] | undefined {
  const prefixFilters: string[] = [];
  if (onlyAi) prefixFilters.push("AI");
  if (onlyMcp) prefixFilters.push("MCP");
  if (onlyVec) prefixFilters.push("VEC");

  if (prefixFilters.length > 0) {
    const filtered = AVAILABLE_RULE_IDS.filter((id) =>
      prefixFilters.some((prefix) => id.startsWith(prefix)),
    );
    if (!rules || rules.length === 0) return filtered;
    const nonMatchingPrefix = rules.filter(
      (id) => !prefixFilters.some((prefix) => id.startsWith(prefix)),
    );
    if (nonMatchingPrefix.length > 0) {
      throw new InvalidArgumentError(
        `Cannot combine --only-* flags with rules from a different category: ${nonMatchingPrefix.join(", ")}.`,
      );
    }
    return rules;
  }

  return rules;
}

function writeFullReport(report: ReportModel, outputPath: string): void {
  const resolved = path.resolve(outputPath);
  const lower = outputPath.toLowerCase();
  let content: string;
  if (lower.endsWith(".json")) {
    content = formatReport(report, "json");
  } else if (lower.endsWith(".md")) {
    content = formatReport(report, "markdown");
  } else if (lower.endsWith(".html")) {
    content = formatReport(report, "html");
  } else {
    throw new InvalidArgumentError(
      `Unsupported output format for "${outputPath}". Use .json, .md, or .html.`,
    );
  }
  fs.writeFileSync(resolved, content, "utf-8");
  process.stdout.write(`Full report written to: ${resolved}\n`);
}

function readPackageVersion(): string {
  try {
    const pkgPath = path.resolve("package.json");
    const raw = fs.readFileSync(pkgPath, "utf-8");
    const parsed = JSON.parse(raw) as { version?: string };
    return parsed.version ?? "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function filterIgnoredBySeverity(
  ignoredFindings: IgnoredFinding[],
  severity: Severity | undefined,
): IgnoredFinding[] {
  if (!severity) return ignoredFindings;
  const threshold = severityValue(severity);
  return ignoredFindings.filter(
    (entry) => severityValue(entry.finding.severity) >= threshold,
  );
}

function severityValue(severity: Severity): number {
  switch (severity) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    default: return 0;
  }
}

function maybePrintContextualHints(
  report: ReportModel,
  baselinePath: string | undefined,
  outputPath: string | undefined,
  previousState: ScanState | undefined,
  hasPolicy: boolean,
): void {
  const hints: string[] = [];

  if (report.summary.total > 10) {
    hints.push("Tip: `--baseline` focuses only on new issues after each commit.");
  }

  if (!outputPath) {
    hints.push("Tip: `--output report.html` generates a shareable, detailed report.");
  }

  if (!baselinePath && previousState?.withoutBaselineRuns === 1) {
    hints.push("Tip: create a baseline with `--baseline .secureai-baseline.json`.");
  }

  if (!hasPolicy && report.summary.total > 0) {
    hints.push("Tip: run `secureai-scan init` to create a policy file and CI workflow.");
  }

  if (report.summary.bySeverity.critical > 0 || report.summary.bySeverity.high > 0) {
    hints.push("Tip: `secureai-scan explain <RULE_ID>` shows a code-level fix for any finding.");
  }

  if (report.summary.total > 0) {
    hints.push("Tip: `secureai-scan threat-model .` builds a THREAT_MODEL.md for security review.");
  }

  if (hints.length > 0) {
    process.stdout.write("\n");
    for (const hint of hints.slice(0, 2)) {
      process.stdout.write(`${hint}\n`);
    }
  }
}

interface ScanState {
  target: string;
  lastRunAt: string;
  withoutBaselineRuns: number;
}

function persistScanRun(
  scanTarget: string,
  baselineUsed: boolean,
  previousState: ScanState | undefined,
): void {
  const statePath = path.join(os.homedir(), ".secureai-scan", "state.json");
  const stateDir = path.dirname(statePath);
  const resolvedTarget = path.resolve(scanTarget);
  const sameTarget = previousState?.target === resolvedTarget;
  const priorWithoutBaseline = sameTarget ? previousState?.withoutBaselineRuns ?? 0 : 0;
  const state = {
    target: resolvedTarget,
    lastRunAt: new Date().toISOString(),
    withoutBaselineRuns: baselineUsed ? 0 : priorWithoutBaseline + 1,
  };
  try {
    fs.mkdirSync(stateDir, { recursive: true });
    fs.writeFileSync(statePath, JSON.stringify(state, null, 2), "utf-8");
  } catch {
    // Non-fatal helper state.
  }
}

function readScanState(scanTarget: string): ScanState | undefined {
  const statePath = path.join(os.homedir(), ".secureai-scan", "state.json");
  try {
    const raw = fs.readFileSync(statePath, "utf-8");
    const state = JSON.parse(raw) as ScanState;
    if (!state.target || !state.lastRunAt || typeof state.withoutBaselineRuns !== "number") {
      return undefined;
    }
    if (path.resolve(scanTarget) !== path.resolve(state.target)) {
      return undefined;
    }
    return state;
  } catch {
    return undefined;
  }
}
