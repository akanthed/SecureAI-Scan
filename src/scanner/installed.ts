import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ts } from "ts-morph";
import type { Finding } from "./types.js";
import { scanMcpConfigs } from "./mcp-config-scanner.js";
import { scanKnownMaliciousPackages } from "./dependency-guard.js";
import { findSkillFiles, scanSkillFiles } from "./skill-scanner.js";
import { scanRepositoryDetailed } from "./scan.js";
import { resolveTarget } from "./fetch-target.js";
import { stripBom } from "../utils/text.js";

/**
 * `secureai-scan installed`: audit the MCP servers and Agent Skills already
 * installed on this machine, across the AI clients that keep per-user config.
 *
 * Config findings come from the same parsers and rules as `scan` (MCP004–006,
 * MCP012, DEP003): each client's server list is normalized into a private
 * staging directory, scanned there, and every finding is mapped back to the
 * real file and line. Only the server entries are staged — never the rest of
 * a client's config (Claude Code's ~/.claude.json also holds session state).
 *
 * `deep` additionally fetches each npm-launched server with `npm pack`
 * (never installed, never executed) and runs the full rule set on its code,
 * plus servers launched from a local path. That is the only network access.
 */

export interface InstalledLocation {
  client: string;
  path: string;
}

export interface InstalledServer {
  client: string;
  configPath: string;
  name: string;
  command?: string;
  args: string[];
}

export interface InstalledScanResult {
  findings: Finding[];
  configs: InstalledLocation[];
  servers: InstalledServer[];
  skillRoots: InstalledLocation[];
  skillCount: number;
  /** Servers whose code was fetched/read and scanned in deep mode. */
  deepScanned: string[];
  /** Servers deep mode could not scan, with the reason. */
  deepSkipped: Array<{ server: string; reason: string }>;
}

export interface InstalledScanOptions {
  home?: string;
  platform?: NodeJS.Platform;
  env?: NodeJS.ProcessEnv;
  deep?: boolean;
  /** Fetch an npm package spec into a directory; injected so tests stay offline. */
  fetchPackage?: (spec: string) => { dir: string; label: string; cleanup: () => void };
}

/** Per-user MCP config locations for the clients we know, on this platform. */
export function installedConfigLocations(home: string, platform: NodeJS.Platform, env: NodeJS.ProcessEnv): InstalledLocation[] {
  const appData = env.APPDATA ?? path.join(home, "AppData", "Roaming");
  const xdgConfig = env.XDG_CONFIG_HOME ?? path.join(home, ".config");
  const userConfigRoot =
    platform === "darwin" ? path.join(home, "Library", "Application Support") : platform === "win32" ? appData : xdgConfig;

  const locations: InstalledLocation[] = [
    { client: "Claude Code", path: path.join(home, ".claude.json") },
    { client: "Claude Desktop", path: path.join(userConfigRoot, "Claude", "claude_desktop_config.json") },
    { client: "Cursor", path: path.join(home, ".cursor", "mcp.json") },
    { client: "Windsurf", path: path.join(home, ".codeium", "windsurf", "mcp_config.json") },
    { client: "Gemini CLI", path: path.join(home, ".gemini", "settings.json") },
    { client: "Amazon Q", path: path.join(home, ".aws", "amazonq", "mcp.json") },
  ];
  for (const [label, dir] of [["VS Code", "Code"], ["VS Code Insiders", "Code - Insiders"]] as const) {
    const user = path.join(userConfigRoot, dir, "User");
    locations.push({ client: label, path: path.join(user, "mcp.json") });
    locations.push({
      client: `Cline (${label})`,
      path: path.join(user, "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"),
    });
    locations.push({
      client: `Roo Code (${label})`,
      path: path.join(user, "globalStorage", "rooveterinaryinc.roo-cline", "settings", "mcp_settings.json"),
    });
  }
  return locations;
}

/** Per-user Agent Skill directories. */
export function installedSkillLocations(home: string): InstalledLocation[] {
  return [
    { client: "Claude Code skills", path: path.join(home, ".claude", "skills") },
    { client: "Claude Code plugins", path: path.join(home, ".claude", "plugins") },
  ];
}

/** Display a path with the home directory abbreviated to `~`. */
function displayPath(filePath: string, home: string): string {
  const relative = path.relative(home, filePath);
  return relative && !relative.startsWith("..") && !path.isAbsolute(relative)
    ? `~/${relative.split(path.sep).join("/")}`
    : filePath;
}

/** JSON with comments and trailing commas (VS Code-style config), never throws. */
function parseConfig(raw: string): unknown {
  try {
    const result = ts.parseConfigFileTextToJson("config.json", raw);
    return result.error ? undefined : result.config;
  } catch {
    return undefined;
  }
}

/**
 * Server entries in a client config: top-level `mcpServers` / `servers`, plus
 * Claude Code's per-project `projects[path].mcpServers`. Names from a project
 * scope keep their project so a finding says where the server is configured.
 */
function serverEntries(config: unknown): Array<[string, unknown]> {
  if (typeof config !== "object" || config === null) return [];
  const obj = config as Record<string, unknown>;
  const entries: Array<[string, unknown]> = [];
  for (const key of ["mcpServers", "servers"]) {
    const container = obj[key];
    if (typeof container === "object" && container !== null) entries.push(...Object.entries(container));
  }
  const projects = obj.projects;
  if (typeof projects === "object" && projects !== null) {
    for (const [project, value] of Object.entries(projects)) {
      const container = (value as Record<string, unknown> | null)?.mcpServers;
      if (typeof container !== "object" || container === null) continue;
      for (const [name, server] of Object.entries(container)) entries.push([`${name} (${project})`, server]);
    }
  }
  return entries;
}

/**
 * The line in the original file that a finding on the staged copy refers to:
 * the first original line containing the longest quoted value from the
 * staged line (a package spec, a URL, an env key).
 */
function originalLine(stagedLines: string[], stagedLine: number, originalLines: string[]): number {
  const quoted = [...(stagedLines[stagedLine - 1] ?? "").matchAll(/"((?:[^"\\]|\\.)+)"/g)].map((m) => m[1]);
  const needles = quoted.sort((a, b) => b.length - a.length);
  for (const needle of needles) {
    const index = originalLines.findIndex((line) => line.includes(needle));
    if (index >= 0) return index + 1;
  }
  return 1;
}

function packageSpec(server: InstalledServer): string | undefined {
  const runner = path.basename(server.command ?? "").toLowerCase();
  if (!["npx", "pnpx", "bunx", "npx.cmd"].includes(runner)) return undefined;
  return server.args.find((arg) => !arg.startsWith("-"));
}

/** A server launched from a local script (`node /abs/server.js`): the package root that script lives in. */
function localServerRoot(server: InstalledServer): string | undefined {
  const runner = path.basename(server.command ?? "").toLowerCase().replace(/\.exe$/, "");
  if (!["node", "python", "python3", "bun", "deno", "tsx", "uv"].includes(runner)) return undefined;
  const script = server.args.find((arg) => !arg.startsWith("-") && path.isAbsolute(arg) && fs.existsSync(arg));
  if (!script) return undefined;
  let dir = fs.statSync(script).isDirectory() ? script : path.dirname(script);
  for (let depth = 0; depth < 4; depth += 1) {
    if (["package.json", "pyproject.toml", "setup.py"].some((file) => fs.existsSync(path.join(dir, file)))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return path.dirname(script);
}

export function scanInstalled(options: InstalledScanOptions = {}): InstalledScanResult {
  const home = options.home ?? os.homedir();
  const platform = options.platform ?? process.platform;
  const env = options.env ?? process.env;

  const result: InstalledScanResult = {
    findings: [],
    configs: [],
    servers: [],
    skillRoots: [],
    skillCount: 0,
    deepScanned: [],
    deepSkipped: [],
  };

  // ── MCP client configs ────────────────────────────────────────────────────
  const staging = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-installed-"));
  try {
    const staged: Array<{ location: InstalledLocation; stagedLines: string[]; originalLines: string[] }> = [];
    for (const location of installedConfigLocations(home, platform, env)) {
      let raw: string;
      try {
        raw = stripBom(fs.readFileSync(location.path, "utf-8"));
      } catch {
        continue;
      }
      const entries = serverEntries(parseConfig(raw));
      if (entries.length === 0) continue;
      result.configs.push(location);
      for (const [name, server] of entries) {
        const value = (server ?? {}) as Record<string, unknown>;
        result.servers.push({
          client: location.client,
          configPath: location.path,
          name,
          command: typeof value.command === "string" ? value.command : undefined,
          args: Array.isArray(value.args) ? value.args.filter((a): a is string => typeof a === "string") : [],
        });
      }
      const dir = path.join(staging, String(staged.length));
      fs.mkdirSync(dir);
      const text = JSON.stringify({ mcpServers: Object.fromEntries(entries) }, null, 2);
      fs.writeFileSync(path.join(dir, ".mcp.json"), text, { mode: 0o600 });
      staged.push({ location, stagedLines: text.split("\n"), originalLines: raw.split(/\r?\n/) });
    }

    for (const finding of [...scanMcpConfigs(staging), ...scanKnownMaliciousPackages(staging)]) {
      const index = Number(finding.file.split(/[\\/]/)[0]);
      const source = staged[index];
      if (!source) continue;
      result.findings.push({
        ...finding,
        file: displayPath(source.location.path, home),
        line: originalLine(source.stagedLines, finding.line, source.originalLines),
        summary: `${source.location.client}: ${finding.summary}`,
      });
    }
  } finally {
    fs.rmSync(staging, { recursive: true, force: true });
  }

  // ── Agent Skills ──────────────────────────────────────────────────────────
  for (const location of installedSkillLocations(home)) {
    if (!fs.existsSync(location.path)) continue;
    const bundles = findSkillFiles(location.path).length;
    if (bundles === 0) continue;
    result.skillRoots.push(location);
    result.skillCount += bundles;
    for (const finding of scanSkillFiles(location.path)) {
      result.findings.push({ ...finding, file: displayPath(path.join(location.path, finding.file), home) });
    }
  }

  // ── Deep: the installed servers' own code ────────────────────────────────
  if (options.deep) {
    const seen = new Set<string>();
    for (const server of result.servers) {
      const label = `${server.name} (${server.client})`;
      const spec = packageSpec(server);
      const localRoot = spec ? undefined : localServerRoot(server);
      const key = spec ?? localRoot;
      if (!key) {
        const runner = path.basename(server.command ?? "remote");
        result.deepSkipped.push({
          server: label,
          reason: runner === "uvx" ? "PyPI packages are not fetched yet" : server.command ? `launched via \`${runner}\`` : "remote server (no local code)",
        });
        continue;
      }
      if (seen.has(key)) continue;
      seen.add(key);

      let target: { dir: string; label: string; cleanup: () => void } | undefined;
      try {
        target = spec
          ? (options.fetchPackage ?? resolveTarget)(spec)
          : { dir: localRoot!, label: displayPath(localRoot!, home), cleanup: () => {} };
      } catch (err) {
        result.deepSkipped.push({ server: label, reason: (err as Error).message.split("\n")[0] });
        continue;
      }
      try {
        const scan = scanRepositoryDetailed(target.dir);
        for (const finding of [...scan.findings, ...scanKnownMaliciousPackages(target.dir)]) {
          result.findings.push({
            ...finding,
            file: `${target.label}/${finding.file.split(path.sep).join("/")}`,
            trace: finding.trace?.map((step) => ({ ...step, file: `${target!.label}/${step.file.split(path.sep).join("/")}` })),
          });
        }
        result.deepScanned.push(target.label);
      } finally {
        target.cleanup();
      }
    }
  }

  return result;
}
