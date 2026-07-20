import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";
import { evidenceConfidence } from "./confidence.js";

/**
 * Scans MCP client configuration files for supply-chain and secret-handling
 * issues. These findings are "proven" evidence: they are parsed facts from
 * the config, not heuristics.
 *
 * Rules:
 *   MCP004 — MCP server launched via npx/uvx without a pinned version
 *   MCP005 — secret value inlined in MCP config env
 *   MCP006 — MCP server URL uses plain http:// (non-localhost)
 */

const MCP_CONFIG_FILENAMES = new Set([
  ".mcp.json",
  "mcp.json",
  "claude_desktop_config.json",
  "mcp_settings.json",
]);

// Directories whose mcp.json is a client config (e.g. .cursor/mcp.json)
const MCP_CONFIG_DIRS = new Set([".cursor", ".vscode", ".gemini", ".codeium"]);

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
]);

export interface McpServerEntry {
  name: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  url?: string;
}

export function findMcpConfigFiles(rootPath: string, skipPaths?: string[]): string[] {
  const results: string[] = [];
  const resolvedRoot = path.resolve(rootPath);
  const skips = (skipPaths ?? []).map((p) => path.resolve(resolvedRoot, p));

  function walk(dir: string, depth: number) {
    if (depth > 6) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (skips.some((s) => full === s || full.startsWith(s + path.sep))) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        if (MCP_CONFIG_FILENAMES.has(entry.name)) {
          results.push(full);
        } else if (entry.name === "mcp.json" && MCP_CONFIG_DIRS.has(path.basename(dir))) {
          results.push(full);
        }
      }
    }
  }

  walk(resolvedRoot, 0);
  return results;
}

export function parseServers(raw: string): { servers: McpServerEntry[]; lines: string[] } {
  const lines = raw.split(/\r?\n/);
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { servers: [], lines };
  }
  if (typeof parsed !== "object" || parsed === null) return { servers: [], lines };

  const obj = parsed as Record<string, unknown>;
  const container =
    (obj.mcpServers as Record<string, unknown> | undefined) ??
    (obj.servers as Record<string, unknown> | undefined) ??
    undefined;
  if (!container || typeof container !== "object") return { servers: [], lines };

  const servers: McpServerEntry[] = [];
  for (const [name, value] of Object.entries(container)) {
    if (typeof value !== "object" || value === null) continue;
    const v = value as Record<string, unknown>;
    servers.push({
      name,
      command: typeof v.command === "string" ? v.command : undefined,
      args: Array.isArray(v.args) ? v.args.filter((a): a is string => typeof a === "string") : undefined,
      env:
        typeof v.env === "object" && v.env !== null
          ? Object.fromEntries(
              Object.entries(v.env as Record<string, unknown>).filter(
                (e): e is [string, string] => typeof e[1] === "string",
              ),
            )
          : undefined,
      url: typeof v.url === "string" ? v.url : typeof v.serverUrl === "string" ? (v.serverUrl as string) : undefined,
    });
  }
  return { servers, lines };
}

/** Find the 1-based line where a string first appears, for report anchoring. */
function lineOf(lines: string[], needle: string): number {
  const idx = lines.findIndex((l) => l.includes(needle));
  return idx >= 0 ? idx + 1 : 1;
}

const SECRET_NAME_HINT = /(key|token|secret|password|passwd|credential)/i;
const ENV_REFERENCE = /^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{env:[^}]+\}$|^\${input:[^}]+\}$/;

function isPinnedPackage(spec: string): boolean {
  // scoped: @scope/name@1.2.3 — unscoped: name@1.2.3
  const at = spec.lastIndexOf("@");
  if (at <= 0) return false;
  const version = spec.slice(at + 1);
  // Pinned when it names an exact-ish version; "latest"/"next" tags are not.
  return /^[~^]?v?\d/.test(version);
}

export function scanMcpConfigs(rootPath: string, skipPaths?: string[]): Finding[] {
  const findings: Finding[] = [];
  const resolvedRoot = path.resolve(rootPath);

  for (const configPath of findMcpConfigFiles(resolvedRoot, skipPaths)) {
    let raw: string;
    try {
      raw = fs.readFileSync(configPath, "utf-8");
    } catch {
      continue;
    }
    const relFile = path.relative(resolvedRoot, configPath);
    const { servers, lines } = parseServers(raw);

    for (const server of servers) {
      // MCP004 — unpinned package execution
      if (server.command && ["npx", "uvx", "pnpx", "bunx"].includes(server.command)) {
        const args = server.args ?? [];
        const pkg = args.find((a) => !a.startsWith("-"));
        if (pkg && !isPinnedPackage(pkg)) {
          findings.push({
            rule_id: "MCP004",
            title: "MCP server runs an unpinned package",
            severity: "high",
            file: relFile,
            line: lineOf(lines, pkg),
            summary: `Server "${server.name}" runs \`${server.command} ${args.join(" ")}\` — the package version is not pinned.`,
            description:
              `Every launch fetches whatever version of "${pkg}" the registry currently serves. If the package is compromised (typosquat, hijacked maintainer, malicious update), the new code runs immediately with this machine's permissions and the MCP server's context access. This is the same class of risk as curl|bash.`,
            recommendation:
              `Pin an exact version: "${pkg}@x.y.z". Review the package before upgrading. For internal servers, install locally and reference the binary path instead of npx.`,
            confidence: evidenceConfidence("proven"),
            evidence: "proven",
          });
        }
      }

      // MCP005 — inline secrets in env
      for (const [key, value] of Object.entries(server.env ?? {})) {
        if (!SECRET_NAME_HINT.test(key)) continue;
        if (value.length < 8) continue;
        if (ENV_REFERENCE.test(value.trim())) continue;
        findings.push({
          rule_id: "MCP005",
          title: "Secret committed in MCP config",
          severity: "critical",
          file: relFile,
          line: lineOf(lines, key),
          summary: `Server "${server.name}" has an inline value for env var "${key}".`,
          description:
            "MCP config files are routinely committed and shared across a team. An API key or token written directly into the config is exposed to everyone with repo access and to any tool that reads the file.",
          recommendation:
            `Reference the environment instead of inlining the value, e.g. "${key}": "\${env:${key}}" (client-dependent syntax), and rotate the exposed credential now.`,
          confidence: evidenceConfidence("proven"),
          evidence: "proven",
        });
      }

      // MCP006 — plaintext HTTP transport
      if (server.url && /^http:\/\//i.test(server.url)) {
        const host = server.url.replace(/^http:\/\//i, "").split(/[/:]/)[0].toLowerCase();
        const isLocal = host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host === "::1";
        if (!isLocal) {
          findings.push({
            rule_id: "MCP006",
            title: "MCP server over plaintext HTTP",
            severity: "high",
            file: relFile,
            line: lineOf(lines, server.url),
            summary: `Server "${server.name}" connects to ${server.url} without TLS.`,
            description:
              "Tool definitions, tool results, and any credentials in headers travel unencrypted. An on-path attacker can read the traffic or swap in malicious tool definitions (an MCP man-in-the-middle is a full agent hijack).",
            recommendation: "Use https:// for all non-localhost MCP servers.",
            confidence: evidenceConfidence("proven"),
            evidence: "proven",
          });
        }
      }
    }
  }

  return findings;
}
