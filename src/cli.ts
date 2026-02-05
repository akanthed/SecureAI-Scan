import { Command, InvalidArgumentError } from "commander";
import { scanRepository, scanRepositoryDetailed } from "./scanner/scan.js";
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
import fs from "node:fs";
import path from "node:path";

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
    .version("0.1.0");

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
    .option("--output <file>", "Write full report to file (.json, .md, or .html)")
    .option("--debug", "Show scanned files and rule/filter info")
    .action(
      (
        path: string,
        options: {
          severity?: Severity;
          rules?: string[];
          onlyAi?: boolean;
          limit?: number;
          output?: string;
          debug?: boolean;
        },
      ) => {
        const selectedRules = resolveRuleSelection(
          options.rules,
          options.onlyAi ?? false,
        );
        const scanResult = options.debug
          ? scanRepositoryDetailed(path, { rules: selectedRules })
          : { findings: scanRepository(path, { rules: selectedRules }), scannedFiles: [] };
        const findings = scanResult.findings;
        const filtered = filterFindingsBySeverity(findings, options.severity);
        const report = buildReport(filtered, {
          tool: "SecureAI-Scan",
          version: readPackageVersion(),
          scannedAt: new Date().toISOString(),
        });

        if (options.output) {
          writeFullReport(report, options.output);
        }

        const terminal = formatTerminalReport(report, options.limit ?? 3);
        process.stdout.write(`${terminal}\n`);

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
