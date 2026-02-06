import { Command, InvalidArgumentError } from "commander";
import { scanRepositoryDetailed, type IgnoredFinding } from "./scanner/scan.js";
import {
  buildReport,
  formatReport,
  formatTerminalReport,
  type ReportModel,
} from "./scanner/reporter.js";
import type { Severity } from "./scanner/types.js";
import { filterFindingsBySeverity } from "./scanner/filters.js";
import { AVAILABLE_RULE_IDS } from "./scanner/rules/index.js";
import { StaticExplainer } from "./scanner/explainer.js";
import { applyBaseline } from "./scanner/baseline.js";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

const ALLOWED_SEVERITIES = ["low", "medium", "high", "critical"] as const;

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

export function runCli(argv: string[]): void {
  const program = new Command();

  program
    .name("secureai-scan")
    .description("Repo-native AI security scanning CLI for LLM-specific risks")
    .version("0.1.0")
    .addHelpText(
      "after",
      "\nKey features:\n  --output <file>   Save a full HTML, Markdown, or JSON report.\n  --baseline <file> Show only new or regressed issues after the first run.\n  // secureai-ignore <RULE_ID>: <reason>   Ignore the next matching finding with a required reason.\n",
    );

  program
    .command("scan")
    .argument("<path>", "Path to the repository to scan")
    .option(
      "-s, --severity <level>",
      "Minimum severity: low | medium | high | critical",
      parseSeverity,
    )
    .option("-r, --rules <list>", "Comma-separated rule IDs", parseRules)
    .option("--only-ai", "Run only AI/LLM-related rules")
    .option("--limit <number>", "Limit number of findings shown", parseLimit)
    .option("--output <file>", "Save a full report as HTML, Markdown, or JSON")
    .option("--baseline <file>", "Track only new or regressed issues using a baseline file")
    .option("--debug", "Show scanned files and rule/filter info")
    .addHelpText(
      "after",
      "\nIgnore annotations:\n  // secureai-ignore <RULE_ID>: <reason>\nIgnores the next matching finding and records it under Ignored Findings.\n",
    )
    .action(
      (
        targetPath: string,
        options: {
          severity?: Severity;
          rules?: string[];
          onlyAi?: boolean;
          limit?: number;
          output?: string;
          baseline?: string;
          debug?: boolean;
        },
      ) => {
        const selectedRules = resolveRuleSelection(
          options.rules,
          options.onlyAi ?? false,
        );
        const previousState = readScanState(targetPath);
        const scanResult = scanRepositoryDetailed(targetPath, { rules: selectedRules });
        const findings = scanResult.findings;
        const filtered = filterFindingsBySeverity(findings, options.severity);
        const filteredIgnored = filterIgnoredBySeverity(scanResult.ignoredFindings, options.severity);

        let outputFindings = filtered;
        if (options.baseline) {
          const baseline = applyBaseline(options.baseline, filtered);
          if (baseline.created) {
            process.stdout.write(
              "Baseline created. Future runs will show only new or regressed issues.\n\n",
            );
          } else {
            outputFindings = baseline.findings;
            process.stdout.write(`New issues since baseline: ${baseline.newOrRegressedCount}\n\n`);
          }
        }

        const report = buildReport(outputFindings, {
          tool: "SecureAI-Scan",
          version: readPackageVersion(),
          scannedAt: new Date().toISOString(),
        }, {
          rootPath: targetPath,
          ignoredFindings: filteredIgnored,
        });

        if (options.output) {
          writeFullReport(report, options.output);
        }

        const terminal = formatTerminalReport(report, options.limit ?? 3);
        process.stdout.write(`${terminal}\n`);

        maybePrintContextualHints(report, options.baseline, options.output, previousState);
        persistScanRun(targetPath, Boolean(options.baseline), previousState);

        if (options.debug) {
          const files = scanResult.scannedFiles;
          process.stderr.write(
            `\n[debug] Scanned files: ${files.length}\n[debug] Rules selected: ${selectedRules?.join(", ") ?? "all"}\n`,
          );
          const preview = files.slice(0, 20);
          if (preview.length > 0) {
            process.stderr.write("[debug] First files:\n");
            for (const file of preview) {
              process.stderr.write(`- ${file}\n`);
            }
            if (files.length > preview.length) {
              process.stderr.write(`[debug] ...and ${files.length - preview.length} more\n`);
            }
          }
        }
      },
    );

  program
    .command("explain")
    .argument("<rule_id>", "Rule ID to explain")
    .action((ruleId: string) => {
      const normalized = ruleId.trim().toUpperCase();
      if (!AVAILABLE_RULE_IDS.includes(normalized)) {
        throw new InvalidArgumentError(
          `Unknown rule ID "${ruleId}". Available rules: ${AVAILABLE_RULE_IDS.join(", ")}.`,
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

      process.stdout.write(`# ${normalized}\n\n`);
      process.stdout.write(`Why this is dangerous:\n${explanation.whyRisky}\n\n`);
      process.stdout.write(`How attackers exploit it:\n${explanation.howExploited}\n\n`);
      process.stdout.write("Fix example:\n\n");
      process.stdout.write("```ts\n");
      process.stdout.write(`${explanation.codeExample}\n`);
      process.stdout.write("```\n");
    });

  program.parse(argv);
}

function resolveRuleSelection(
  rules: string[] | undefined,
  onlyAi: boolean,
): string[] | undefined {
  if (!onlyAi) {
    return rules;
  }
  const aiRules = AVAILABLE_RULE_IDS.filter((id) => id.startsWith("AI"));
  if (!rules || rules.length === 0) {
    return aiRules;
  }
  const nonAi = rules.filter((id) => !id.startsWith("AI"));
  if (nonAi.length > 0) {
    throw new InvalidArgumentError(
      `--only-ai cannot be combined with non-AI rules: ${nonAi.join(", ")}.`,
    );
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
  process.stdout.write(`\nFull report written to: ${resolved}\n`);
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
  if (!severity) {
    return ignoredFindings;
  }

  const threshold = severityValue(severity);
  return ignoredFindings.filter((entry) => severityValue(entry.finding.severity) >= threshold);
}

function severityValue(severity: Severity): number {
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

function maybePrintContextualHints(
  report: ReportModel,
  baselinePath: string | undefined,
  outputPath: string | undefined,
  previousState: ScanState | undefined,
): void {
  if (report.summary.total > 10) {
    process.stdout.write(
      "\nTip: Large result sets can be noisy. Use --baseline to track only new issues.\n",
    );
  }

  if (!outputPath) {
    process.stdout.write("Tip: Generate a shareable report with --output report.html\n");
  }

  if (!baselinePath && previousState?.withoutBaselineRuns === 1) {
    process.stdout.write(
      "Tip: Create a baseline to focus on new issues:\nnpx secureai-scan scan . --baseline secureai-baseline.json\n",
    );
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
