import * as vscode from "vscode";
import * as path from "node:path";
import * as fs from "node:fs";
import * as os from "node:os";
import { execFile } from "node:child_process";

/**
 * Mirrors src/scanner/reporter.ts's ReportModel/ReportGroup/ReportOccurrence
 * shape (the CLI's `--output <file>.json` schema). Kept as a local subset —
 * not imported from the CLI package, since this extension only ever reads
 * the CLI's serialized JSON output, never its internals.
 */
interface ReportOccurrence {
  file: string;
  line: number;
  summary: string;
  evidence: "proven" | "likely" | "heuristic";
}

interface ReportGroup {
  ruleId: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  evidence: "proven" | "likely" | "heuristic";
  recommendation: string;
  occurrences: ReportOccurrence[];
}

interface ReportModel {
  groups: ReportGroup[];
  summary: { total: number };
}

const SCANNABLE_LANGUAGES = new Set([
  "typescript",
  "typescriptreact",
  "javascript",
  "javascriptreact",
  "python",
]);

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let statusItem: vscode.StatusBarItem;
let scanSeq = 0;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("secureaiScan");
  output = vscode.window.createOutputChannel("SecureAI-Scan");
  statusItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusItem.name = "SecureAI-Scan";
  statusItem.text = "$(shield) SecureAI-Scan";
  statusItem.tooltip = "Run SecureAI-Scan on this workspace";
  statusItem.command = "secureaiScan.scanWorkspace";
  statusItem.show();

  context.subscriptions.push(diagnostics, output, statusItem);

  context.subscriptions.push(
    vscode.commands.registerCommand("secureaiScan.scanWorkspace", async () => {
      const folder = pickWorkspaceFolder();
      if (folder) await runScan(context, folder);
    }),
    vscode.commands.registerCommand("secureaiScan.scanFile", async () => {
      const doc = vscode.window.activeTextEditor?.document;
      const folder = doc ? vscode.workspace.getWorkspaceFolder(doc.uri) : undefined;
      if (folder) {
        await runScan(context, folder);
      } else {
        vscode.window.showWarningMessage("SecureAI-Scan: open a file inside a workspace folder first.");
      }
    }),
    vscode.commands.registerCommand("secureaiScan.clearFindings", () => {
      diagnostics.clear();
      statusItem.text = "$(shield) SecureAI-Scan";
    }),
  );

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      const config = vscode.workspace.getConfiguration("secureaiScan");
      if (!config.get<boolean>("scanOnSave", true)) return;
      if (!SCANNABLE_LANGUAGES.has(doc.languageId) && !isRelevantConfigFile(doc.fileName)) return;

      const folder = vscode.workspace.getWorkspaceFolder(doc.uri);
      if (folder) await runScan(context, folder);
    }),
  );
}

export function deactivate(): void {
  diagnostics?.dispose();
  output?.dispose();
  statusItem?.dispose();
}

function isRelevantConfigFile(fileName: string): boolean {
  const base = path.basename(fileName);
  return base === ".mcp.json" || base === "claude_desktop_config.json" || base === "SKILL.md";
}

function pickWorkspaceFolder(): vscode.WorkspaceFolder | undefined {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("SecureAI-Scan: open a folder or workspace first.");
    return undefined;
  }
  return folders[0];
}

function resolveCliPath(context: vscode.ExtensionContext): string {
  const configured = vscode.workspace.getConfiguration("secureaiScan").get<string>("cliPath", "");
  if (configured && configured.trim().length > 0) return configured;
  return path.join(context.extensionPath, "node_modules", "secureai-scan", "dist", "index.js");
}

async function runScan(context: vscode.ExtensionContext, folder: vscode.WorkspaceFolder): Promise<void> {
  const cliPath = resolveCliPath(context);
  if (!fs.existsSync(cliPath)) {
    vscode.window.showErrorMessage(
      `SecureAI-Scan: CLI not found at ${cliPath}. Reinstall the extension, or set "secureaiScan.cliPath" in settings.`,
    );
    return;
  }

  const config = vscode.workspace.getConfiguration("secureaiScan");
  const paranoid = config.get<boolean>("paranoid", false);
  const minSeverity = config.get<string>("minSeverity", "low");

  const seq = ++scanSeq;
  statusItem.text = "$(sync~spin) SecureAI-Scan: scanning…";
  const outFile = path.join(os.tmpdir(), `secureai-scan-vscode-${process.pid}-${seq}.json`);

  const args = ["scan", folder.uri.fsPath, "--output", outFile];
  if (paranoid) args.push("--paranoid");
  if (minSeverity !== "low") args.push("--severity", minSeverity);

  output.appendLine(`$ node ${cliPath} ${args.join(" ")}`);

  execFile("node", [cliPath, ...args], { cwd: folder.uri.fsPath, maxBuffer: 32 * 1024 * 1024 }, (_err, stdout, stderr) => {
    if (seq !== scanSeq) return; // superseded by a newer scan
    if (stdout) output.append(stdout);
    if (stderr) output.append(stderr);

    let report: ReportModel;
    try {
      report = JSON.parse(fs.readFileSync(outFile, "utf-8"));
    } catch (readErr) {
      // A nonzero exit with no output file means the CLI itself failed
      // (bad args, crash) — --fail-on findings still write the report.
      statusItem.text = "$(shield) SecureAI-Scan";
      output.appendLine(`SecureAI-Scan: could not read report — ${String(readErr)}`);
      vscode.window.showErrorMessage("SecureAI-Scan: scan failed — see the SecureAI-Scan output channel.");
      return;
    } finally {
      fs.rm(outFile, { force: true }, () => {});
    }

    applyDiagnostics(folder, report);
    const count = report.summary.total;
    statusItem.text = count > 0 ? `$(shield) SecureAI-Scan: ${count}` : "$(shield) SecureAI-Scan: 0";
    statusItem.tooltip =
      count > 0
        ? `SecureAI-Scan found ${count} finding(s). Click to re-scan.`
        : "SecureAI-Scan: no findings. Click to re-scan.";
  });
}

function applyDiagnostics(folder: vscode.WorkspaceFolder, report: ReportModel): void {
  // Only replace diagnostics for files under this workspace folder — a
  // multi-root workspace scanning one folder must not clear another
  // folder's still-valid findings.
  for (const [uri] of diagnostics) {
    if (uri.fsPath.startsWith(folder.uri.fsPath)) diagnostics.delete(uri);
  }

  const byFile = new Map<string, vscode.Diagnostic[]>();
  for (const group of report.groups) {
    for (const occ of group.occurrences) {
      const absPath = path.isAbsolute(occ.file) ? occ.file : path.join(folder.uri.fsPath, occ.file);
      const line = Math.max(0, occ.line - 1);
      const range = new vscode.Range(line, 0, line, Number.MAX_SAFE_INTEGER);
      const diagnostic = new vscode.Diagnostic(range, occ.summary, severityToVscode(group.severity));
      diagnostic.source = "secureai-scan";
      diagnostic.code = group.ruleId;
      diagnostic.tags = [];
      const detail = [`[${group.evidence}] ${group.title}`, group.recommendation].join("\n");
      diagnostic.relatedInformation = [
        new vscode.DiagnosticRelatedInformation(
          new vscode.Location(vscode.Uri.file(absPath), range),
          detail,
        ),
      ];
      const list = byFile.get(absPath) ?? [];
      list.push(diagnostic);
      byFile.set(absPath, list);
    }
  }

  for (const [absPath, list] of byFile) {
    diagnostics.set(vscode.Uri.file(absPath), list);
  }
}

function severityToVscode(severity: ReportGroup["severity"]): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
  }
}
