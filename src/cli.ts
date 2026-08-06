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
import { catalogFor, OWASP_LLM_TOP10_VERSION } from "./scanner/catalog.js";
import { applyBaseline } from "./scanner/baseline.js";
import { scanDependencyFilesForRisks, scanKnownMaliciousPackages } from "./scanner/dependency-guard.js";
import { loadPolicy, writeDefaultPolicy, writeGithubWorkflow } from "./scanner/policy.js";
import { generateThreatModel } from "./scanner/threat-model.js";
import { generateBom, formatBomMarkdown } from "./scanner/bom.js";
import { getOwnVersion } from "./utils/version.js";
import { scanSkillFiles, findSkillFiles } from "./scanner/skill-scanner.js";
import { resolveTarget } from "./scanner/fetch-target.js";
import fs from "node:fs";
import path from "node:path";

const ALLOWED_SEVERITIES = ["low", "medium", "high", "critical"] as const;

// ─── Helpers ────────────────────────────────────────────────────────────────

function parseSeverity(value: string): Severity {
  const normalized = value.trim().toLowerCase();
  if (ALLOWED_SEVERITIES.includes(normalized as Severity)) {
    return normalized as Severity;
  }
  throw new InvalidArgumentError(
    `Invalid severity "${value}". Expected one of: ${ALLOWED_SEVERITIES.join(", ")}.`,
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

function severityValue(severity: Severity): number {
  switch (severity) {
    case "critical": return 4;
    case "high": return 3;
    case "medium": return 2;
    case "low": return 1;
    default: return 0;
  }
}

// ─── CLI entry ───────────────────────────────────────────────────────────────

export async function runCli(argv: string[]): Promise<void> {
  const program = new Command();

  program
    .name("secureai-scan")
    .description("AI security scanner — proves LLM, MCP, and RAG vulnerabilities with dataflow evidence")
    .version(getOwnVersion())
    .addHelpText(
      "after",
      [
        "",
        "Quick start:",
        "  secureai-scan scan .                  Scan current repo (proven + likely findings)",
        "  secureai-scan scan . --paranoid       Include heuristic-tier findings",
        "  secureai-scan scan . --output r.sarif SARIF for GitHub code scanning",
        "  secureai-scan bom .                   AI Bill of Materials (SDKs, models, MCP servers)",
        "  secureai-scan explain AI001           Fix guide for a rule",
        "  secureai-scan init                    Policy file + CI workflow",
        "",
        "Scan before you install (no clone, no config — nothing fetched is ever executed):",
        "  secureai-scan skill anthropics/skills     Scan an Agent Skill by owner/repo, URL, or local path",
        "  secureai-scan mcp some-mcp-server-package Scan an MCP server by npm name, git URL, or local path",
        "",
        "Suppress a reviewed finding in code:",
        "  // secureai-ignore AI001: reviewed, sanitized via allowlist",
        "",
        `Rules: ${AVAILABLE_RULE_IDS.join(", ")}`,
      ].join("\n"),
    );

  // ── scan ─────────────────────────────────────────────────────────────────
  program
    .command("scan")
    .argument("<path>", "Path to the repository to scan")
    // Everyday flags
    .option("-s, --severity <level>", "Minimum severity: low | medium | high | critical", parseSeverity)
    .option("--paranoid", "Include heuristic-tier findings (hidden by default)")
    .option("--output <file>", "Save a full report as .sarif, .json, .md, or .html")
    .option("--fail-on <severity>", "Exit 1 if findings at/above this severity exist", parseSeverity)
    // Scope which rules run
    .option("-r, --rules <list>", "Comma-separated rule IDs to run, e.g. AI001,MCP007", parseRules)
    .option("--only-ai", "Run only AI/LLM rules (AI001–AI012)")
    .option("--only-mcp", "Run only MCP rules (MCP001–MCP010)")
    .option("--only-vec", "Run only Vector/RAG rules (VEC001–VEC004)")
    .option("--only-skl", "Run only Agent Skill rules (SKL001–SKL005)")
    .option(
      "--check-dependencies",
      "Also check package.json/requirements.txt against the npm/PyPI registry for typos and hallucinated packages (DEP001/DEP002). Not required for DEP003 (known-malicious packages) — that runs offline on every scan",
    )
    // CI / workflow
    .option("--baseline <file>", "Track only new/changed issues using a baseline file")
    .option("--policy <file>", "Path to a .secureai-policy.json file (auto-detected if omitted)")
    // Advanced / debugging
    .option("--min-confidence <0-1>", "Advanced: hide findings below this exact confidence score (0.9 proven / 0.65 likely / 0.35 heuristic) — for finer control than --paranoid alone", parseConfidence)
    .option("--limit <number>", "Max rule groups shown in terminal (default: 10)", parseLimit)
    .option("--debug", "Show scanned files and rule metadata")
    .action(
      async (
        targetPath: string,
        options: {
          severity?: Severity;
          rules?: string[];
          onlyAi?: boolean;
          onlyMcp?: boolean;
          onlyVec?: boolean;
          onlySkl?: boolean;
          paranoid?: boolean;
          limit?: number;
          output?: string;
          baseline?: string;
          policy?: string;
          failOn?: Severity;
          minConfidence?: number;
          checkDependencies?: boolean;
          debug?: boolean;
        },
      ) => {
        const startedAt = Date.now();

        if (!fs.existsSync(targetPath)) {
          process.stderr.write(`Error: path does not exist: ${targetPath}\n`);
          process.exit(1);
        }

        const policyResult = options.policy
          ? loadPolicy(path.dirname(options.policy))
          : loadPolicy(targetPath);
        if (policyResult) {
          process.stdout.write(`Policy loaded: ${policyResult.policyPath}\n`);
        }
        const activePolicy = policyResult?.policy ?? {};

        const selectedRules = resolveRuleSelection(
          options.rules ?? (activePolicy.onlyRules?.length ? activePolicy.onlyRules : undefined),
          options.onlyAi ?? false,
          options.onlyMcp ?? false,
          options.onlyVec ?? false,
          options.onlySkl ?? false,
        );

        // Requesting DEP001/DEP002 explicitly via --rules is a clear signal
        // to run the registry check they depend on — requiring a second,
        // separate --check-dependencies flag on top of an explicit --rules
        // selection was a silent no-op trap (the rule ID validated fine,
        // then produced zero output with no indication why).
        const checkDependencies =
          (options.checkDependencies ?? false) ||
          (selectedRules?.some((id) => id === "DEP001" || id === "DEP002") ?? false);

        // The scan below is synchronous, CPU-bound work with no natural yield
        // point for an animated spinner — but a single line up front is enough
        // to stop a multi-second scan on a large repo from looking hung.
        if (process.stderr.isTTY) {
          process.stderr.write(`Scanning ${targetPath}...\n`);
        }

        const scanResult = scanRepositoryDetailed(targetPath, {
          rules: selectedRules,
          skipPaths: activePolicy.skipPaths,
          blockedRules: activePolicy.blockedRules,
        });
        const findings: Finding[] = [...scanResult.findings];

        if (checkDependencies) {
          const depFindings = await scanDependencyFilesForRisks({ rootPath: targetPath });
          findings.push(...depFindings);
        }

        // DEP003 uses the bundled advisory list — offline, so it runs on
        // every scan rather than behind --check-dependencies.
        const advisoryFindings = scanKnownMaliciousPackages(targetPath, activePolicy.skipPaths).filter(
          (f) =>
            (!selectedRules || selectedRules.includes(f.rule_id)) &&
            !activePolicy.blockedRules?.includes(f.rule_id),
        );
        findings.push(...advisoryFindings);

        // Evidence filter: heuristic findings are hidden unless --paranoid.
        const paranoid = options.paranoid ?? false;
        const evidenceFiltered = paranoid
          ? findings
          : findings.filter((f) => f.evidence !== "heuristic");
        const hiddenHeuristic = findings.length - evidenceFiltered.length;

        // Optional numeric confidence filter (CLI > policy; no hidden default).
        const minConfidence = options.minConfidence ?? activePolicy.minConfidence;
        const confidenceFiltered =
          minConfidence !== undefined
            ? evidenceFiltered.filter((f) => f.confidence >= minConfidence)
            : evidenceFiltered;

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
            process.stdout.write("Baseline created. Future runs will show only new or changed issues.\n");
          } else {
            outputFindings = baseline.findings;
          }
        }

        const filesScanned =
          scanResult.scannedFiles.length + (scanResult.pythonFiles?.length ?? 0);

        const report = buildReport(
          outputFindings,
          {
            tool: "SecureAI-Scan",
            version: getOwnVersion(),
            scannedAt: new Date().toISOString(),
          },
          {
            rootPath: targetPath,
            ignoredFindings: filteredIgnored,
            baselineDiff,
            hiddenHeuristic,
            filesScanned,
            durationMs: Date.now() - startedAt,
          },
        );

        if (options.output) {
          writeFullReport(report, options.output);
        }

        process.stdout.write(`${formatTerminalReport(report, options.limit ?? 10)}\n`);

        if (options.debug) {
          const tsFiles = scanResult.scannedFiles;
          const pyFiles = scanResult.pythonFiles ?? [];
          process.stderr.write(
            `\n[debug] Scanned: ${tsFiles.length} TS/JS file(s), ${pyFiles.length} Python file(s) | Rules: ${selectedRules?.join(", ") ?? "all"} | paranoid: ${paranoid}\n`,
          );
          for (const f of [...tsFiles, ...pyFiles].slice(0, 20)) process.stderr.write(`  ${f}\n`);
        }

        // Fail threshold: CLI flag > policy.
        const failSeverity = options.failOn ?? activePolicy.failOnSeverity;
        if (failSeverity) {
          const failing = outputFindings.filter(
            (f) => severityValue(f.severity) >= severityValue(failSeverity),
          );
          if (failing.length > 0) {
            process.stderr.write(
              `\nFailing: ${failing.length} finding(s) at or above "${failSeverity}" severity.\n`,
            );
            process.exit(1);
          }
        }
      },
    );

  // ── skill ────────────────────────────────────────────────────────────────
  // The pre-install wedge: scan a single Agent Skill before you trust it —
  // no clone, no repo, no config. `target` is a local path, a full git URL,
  // or a GitHub "owner/repo" shorthand (a subdirectory containing SKILL.md
  // works too, since scanSkillFiles walks the whole fetched tree).
  program
    .command("skill")
    .argument("<target>", "Local path, git URL, or \"owner/repo\" of an Agent Skill to scan before installing")
    .option("-s, --severity <level>", "Minimum severity: low | medium | high | critical", parseSeverity)
    .option("--paranoid", "Include heuristic-tier findings (hidden by default)")
    .option("--output <file>", "Save a full report as .sarif, .json, .md, or .html")
    .option("--fail-on <severity>", "Exit 1 if findings at/above this severity exist", parseSeverity)
    .option("--limit <number>", "Max rule groups shown in terminal (default: 10)", parseLimit)
    .option("--keep", "Do not delete the fetched copy after scanning (prints its path)")
    .description("Fetch and scan a single Agent Skill for poisoning/evasion before you install it (SKL001–SKL005)")
    .action(async (target: string, options: SkillOrMcpOptions) => {
      await runFetchAndScan(target, "skill", options);
    });

  // ── mcp ──────────────────────────────────────────────────────────────────
  // Same wedge, for an MCP server: a bare npm package name, a git URL, or a
  // local path. Runs the full rule set (not just MCP*) since a server
  // package can carry any in-scope risk — an LLM call, a leaked secret, a
  // known-malicious dependency — not only tool-poisoning.
  program
    .command("mcp")
    .argument("<target>", "npm package name, git URL, or local path of an MCP server to scan before installing")
    .option("-s, --severity <level>", "Minimum severity: low | medium | high | critical", parseSeverity)
    .option("--paranoid", "Include heuristic-tier findings (hidden by default)")
    .option("--output <file>", "Save a full report as .sarif, .json, .md, or .html")
    .option("--fail-on <severity>", "Exit 1 if findings at/above this severity exist", parseSeverity)
    .option("--limit <number>", "Max rule groups shown in terminal (default: 10)", parseLimit)
    .option("--keep", "Do not delete the fetched copy after scanning (prints its path)")
    .description("Fetch and scan an MCP server package before you install it (full rule set + DEP003 advisories)")
    .action(async (target: string, options: SkillOrMcpOptions) => {
      await runFetchAndScan(target, "mcp", options);
    });

  // ── explain ──────────────────────────────────────────────────────────────
  program
    .command("explain")
    .argument("<rule_id>", "Rule ID to explain (e.g. AI001, MCP004, VEC003)")
    .description("Show why a rule exists, how it's exploited, and a concrete fix example")
    .action((ruleId: string) => {
      const normalized = ruleId.trim().toUpperCase();
      if (!AVAILABLE_RULE_IDS.includes(normalized)) {
        throw new InvalidArgumentError(
          `Unknown rule ID "${ruleId}". Available: ${AVAILABLE_RULE_IDS.join(", ")}.`,
        );
      }
      const catalog = catalogFor(normalized);
      const explainer = new StaticExplainer();
      const explanation = explainer.explain({
        rule_id: normalized,
        title: catalog?.title ?? normalized,
        severity: catalog?.severity ?? "medium",
        file: "",
        line: 0,
        summary: "",
        description: "",
        recommendation: "",
        confidence: 0,
        evidence: "likely",
      });

      const divider = "─".repeat(48);
      process.stdout.write(`\n# ${normalized} — ${catalog?.title ?? explanation.summary}\n\n`);
      if (catalog) {
        const tags = [
          `Severity: ${catalog.severity}`,
          `OWASP ${catalog.owasp}:${OWASP_LLM_TOP10_VERSION} (${catalog.owaspName})`,
          catalog.euAiAct ? `EU AI Act ${catalog.euAiAct}` : "",
        ].filter(Boolean);
        process.stdout.write(`${tags.join("  ·  ")}\n\n`);
      }
      process.stdout.write(`Why this is dangerous\n${divider}\n${explanation.whyRisky}\n\n`);
      process.stdout.write(`How attackers exploit it\n${divider}\n${explanation.howExploited}\n\n`);
      process.stdout.write(`How to fix it\n${divider}\n${explanation.howToFix}\n\n`);
      process.stdout.write(`Code example\n${divider}\n`);
      process.stdout.write("```ts\n" + explanation.codeExample + "\n```\n\n");
    });

  // ── bom ──────────────────────────────────────────────────────────────────
  program
    .command("bom")
    .argument("[path]", "Repository to inventory (default: current directory)", ".")
    .option("--output <file>", "Write to file (.json or .md); prints markdown otherwise")
    .description("Generate an AI Bill of Materials: SDKs, models, vector stores, agent frameworks, MCP servers")
    .action((targetPath: string, options: { output?: string }) => {
      const bom = generateBom(targetPath);
      if (options.output) {
        const resolved = path.resolve(options.output);
        const content = options.output.toLowerCase().endsWith(".json")
          ? JSON.stringify(bom, null, 2)
          : formatBomMarkdown(bom);
        fs.writeFileSync(resolved, content, "utf-8");
        process.stdout.write(`AI-BOM written to: ${resolved} (${bom.components.length} component(s))\n`);
      } else {
        process.stdout.write(formatBomMarkdown(bom) + "\n");
      }
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

      const content = generateThreatModel(findings, {
        scannedAt: new Date().toISOString(),
        version: getOwnVersion(),
        rootPath: path.resolve(targetPath),
      });

      const outPath = path.resolve(options.output ?? path.join(targetPath, "THREAT_MODEL.md"));
      fs.writeFileSync(outPath, content, "utf-8");
      process.stdout.write(`Threat model written to: ${outPath} (${findings.length} finding(s) included)\n`);
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

      const policyPath = writeDefaultPolicy(resolved);
      process.stdout.write(`✓ Policy file created: ${policyPath}\n`);

      if (options.ci) {
        try {
          const workflowPath = writeGithubWorkflow(resolved);
          process.stdout.write(`✓ CI workflow created: ${workflowPath}\n`);
          process.stdout.write("  Findings will appear in GitHub code scanning via SARIF upload.\n");
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          process.stdout.write(`  (Skipped CI workflow — could not write .github/workflows/: ${reason})\n`);
        }
      }

      process.stdout.write("\nNext steps:\n");
      process.stdout.write("  1. secureai-scan scan .                     scan now\n");
      process.stdout.write("  2. secureai-scan scan . --baseline .secureai-baseline.json\n");
      process.stdout.write("  3. secureai-scan bom . --output AI_BOM.md   inventory your AI stack\n");
      process.stdout.write("  4. secureai-scan explain <RULE_ID>          fix guide per rule\n\n");
    });

  await program.parseAsync(argv);
}

// ─── Internal helpers ────────────────────────────────────────────────────────

function resolveRuleSelection(
  rules: string[] | undefined,
  onlyAi: boolean,
  onlyMcp: boolean,
  onlyVec: boolean,
  onlySkl: boolean,
): string[] | undefined {
  const prefixFilters: string[] = [];
  if (onlyAi) prefixFilters.push("AI");
  if (onlyMcp) prefixFilters.push("MCP");
  if (onlyVec) prefixFilters.push("VEC");
  if (onlySkl) prefixFilters.push("SKL");

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

interface SkillOrMcpOptions {
  severity?: Severity;
  paranoid?: boolean;
  output?: string;
  failOn?: Severity;
  limit?: number;
  keep?: boolean;
}

/**
 * Shared implementation for `skill` and `mcp`: fetch the target without
 * executing anything it contains, scan it, report, then clean up. The two
 * commands differ only in which scan function runs and what "nothing found"
 * means for that target type.
 */
async function runFetchAndScan(
  target: string,
  mode: "skill" | "mcp",
  options: SkillOrMcpOptions,
): Promise<void> {
  const startedAt = Date.now();
  process.stdout.write(`Fetching ${target}...\n`);

  let resolved: ReturnType<typeof resolveTarget>;
  try {
    resolved = resolveTarget(target);
  } catch (err) {
    process.stderr.write(`\n${(err as Error).message}\n`);
    process.exitCode = 1;
    return;
  }

  try {
    process.stdout.write(`Scanning ${resolved.label}${resolved.kind !== "local" ? " (fetched, not installed)" : ""}...\n`);

    let findings: Finding[];
    let filesScanned: number;
    if (mode === "skill") {
      const bundleCount = findSkillFiles(resolved.dir).length;
      if (bundleCount === 0) {
        process.stdout.write("\nNo SKILL.md found under this target — nothing to scan.\n");
        return;
      }
      findings = scanSkillFiles(resolved.dir);
      filesScanned = bundleCount;
    } else {
      const scanResult = scanRepositoryDetailed(resolved.dir);
      findings = [...scanResult.findings];
      // DEP003 is the single most relevant check for "should I install this
      // package" — it runs unconditionally here, same as in `scan`.
      findings.push(...scanKnownMaliciousPackages(resolved.dir));
      filesScanned = scanResult.scannedFiles.length + (scanResult.pythonFiles?.length ?? 0);
    }

    const paranoid = options.paranoid ?? false;
    const evidenceFiltered = paranoid ? findings : findings.filter((f) => f.evidence !== "heuristic");
    const hiddenHeuristic = findings.length - evidenceFiltered.length;
    const filtered = filterFindingsBySeverity(evidenceFiltered, options.severity);

    const report = buildReport(
      filtered,
      { tool: "SecureAI-Scan", version: getOwnVersion(), scannedAt: new Date().toISOString() },
      {
        rootPath: resolved.dir,
        ignoredFindings: [],
        hiddenHeuristic,
        filesScanned,
        durationMs: Date.now() - startedAt,
      },
    );

    if (options.output) {
      writeFullReport(report, options.output);
    }
    process.stdout.write(`${formatTerminalReport(report, options.limit ?? 10)}\n`);

    if (options.failOn) {
      const failing = filtered.filter((f) => severityValue(f.severity) >= severityValue(options.failOn!));
      if (failing.length > 0) {
        process.stderr.write(`\nFailing: ${failing.length} finding(s) at or above "${options.failOn}" severity.\n`);
        process.exitCode = 1;
      }
    }
  } finally {
    if (options.keep) {
      process.stdout.write(`\nKept fetched copy at: ${resolved.dir}\n`);
    } else {
      resolved.cleanup();
    }
  }
}

function writeFullReport(report: ReportModel, outputPath: string): void {
  const resolved = path.resolve(outputPath);
  const lower = outputPath.toLowerCase();
  let content: string;
  if (lower.endsWith(".sarif")) {
    content = formatReport(report, "sarif");
  } else if (lower.endsWith(".json")) {
    content = formatReport(report, "json");
  } else if (lower.endsWith(".md")) {
    content = formatReport(report, "markdown");
  } else if (lower.endsWith(".html")) {
    content = formatReport(report, "html");
  } else {
    throw new InvalidArgumentError(
      `Unsupported output format for "${outputPath}". Use .sarif, .json, .md, or .html.`,
    );
  }
  fs.writeFileSync(resolved, content, "utf-8");
  process.stdout.write(`Report written to: ${resolved}\n`);
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
