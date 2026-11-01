import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";

/**
 * Resolves a "scan this before you trust it" target — a local path, a git
 * URL, or a bare npm package name — into a local directory, without ever
 * executing the target's code.
 *
 * This is the pre-install wedge: the decisive moment for an MCP server or
 * Agent Skill is before it's added to `.mcp.json` or dropped into
 * `~/.claude/skills/`, not after it's already committed. `secureai-scan skill
 * <url>` / `secureai-scan mcp <package>` exist to answer "should I trust
 * this" at that moment, with no clone, no config, no prior trust required.
 *
 * Safety is the whole point: an npm package is fetched with `npm pack`
 * (downloads the tarball only — no `install`, no lifecycle scripts) and a
 * git target is fetched with `git clone --depth 1` (no build step, no
 * `npm install` inside it). Nothing this module fetches is ever executed.
 */

export type TargetKind = "local" | "git" | "npm";

export interface ResolvedTarget {
  dir: string;
  kind: TargetKind;
  /** What was actually resolved, for display (e.g. the exact npm version fetched). */
  label: string;
  /** Deletes the temp directory, if one was created. Safe to call multiple times. */
  cleanup: () => void;
}

// A spec is attacker-influenced input: the `installed --deep` path takes it from
// a client config and the MCP `scan_untrusted_target` tool takes it from the
// model. Only these shapes are ever handed to git or npm; anything else is
// refused rather than guessed at, so neither tool can read part of a spec as
// an option (`--upload-pack=...`, `--registry=...`) or a shell metacharacter.
const GIT_URL_RE = /^(?:https?:\/\/\S+|git@[\w.-]+:\S+|[\w-]+\/[\w.-]+)$/;
const NPM_SPEC_RE = /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*(?:@[\w.+-]+)?$/i;

export function classify(spec: string): TargetKind {
  if (spec.startsWith("-")) {
    throw new Error(`Refusing target "${spec}": a leading "-" would be read as a command-line option.`);
  }
  if (fs.existsSync(spec)) return "local";
  if (GIT_URL_RE.test(spec)) return "git";
  if (NPM_SPEC_RE.test(spec)) return "npm";
  throw new Error(
    `"${spec}" is not a local path, an https:// or git@ URL, an owner/repo, or a registry package ` +
      `(name, name@version, @scope/name). Other forms (git+ssh:, file:, tarball URLs, version ranges) are not fetched.`,
  );
}

function normalizeGitUrl(spec: string): string {
  if (spec.startsWith("http://") || spec.startsWith("https://") || spec.startsWith("git@")) {
    return spec;
  }
  // Short form: "owner/repo" -> GitHub.
  return `https://github.com/${spec}.git`;
}

function mkTempDir(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanupDir(dir: string): () => void {
  let done = false;
  return () => {
    if (done) return;
    done = true;
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {
      /* best-effort */
    }
  };
}

function fetchGit(spec: string): ResolvedTarget {
  const url = normalizeGitUrl(spec);
  const dir = mkTempDir("secureai-scan-git-");
  try {
    execFileSync("git", ["clone", "--depth", "1", "--quiet", "--", url, dir], {
      stdio: ["ignore", "ignore", "pipe"],
    });
  } catch (err) {
    cleanupDir(dir)();
    const stderr = (err as { stderr?: Buffer })?.stderr?.toString().trim();
    throw new Error(`Could not clone "${url}"${stderr ? `: ${stderr}` : "."}`);
  }
  return { dir, kind: "git", label: url, cleanup: cleanupDir(dir) };
}

/**
 * `npm pack` downloads the package tarball to disk without installing it —
 * no `node_modules`, no lifecycle scripts (`preinstall`/`postinstall`) ever
 * run. That property is not incidental; it is the reason this command is
 * safe to run against a package you have not decided to trust yet.
 */
function fetchNpm(spec: string): ResolvedTarget {
  const dir = mkTempDir("secureai-scan-npm-");
  let packedName: string;
  try {
    // On Windows npm ships as npm.cmd, which execFileSync cannot start without
    // a shell, and with shell:true Node joins the arguments into one cmd.exe
    // line WITHOUT quoting them. That is only safe because `spec` has already
    // passed NPM_SPEC_RE (no whitespace, quotes, or cmd metacharacters, and it
    // cannot start with "-"), and because the destination is "." under `cwd`
    // rather than a temp path that may contain spaces. --ignore-scripts keeps
    // npm from running prepare/prepack for anything it resolves.
    const out = execFileSync("npm", ["pack", "--ignore-scripts", "--silent", "--pack-destination", ".", "--", spec], {
      cwd: dir,
      encoding: "utf-8",
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32",
    });
    packedName = out.trim().split(/\r?\n/).pop() ?? "";
  } catch (err) {
    cleanupDir(dir)();
    const stderr = (err as { stderr?: Buffer })?.stderr?.toString().trim();
    throw new Error(`Could not fetch npm package "${spec}"${stderr ? `: ${stderr}` : "."}`);
  }

  const tarballPath = path.join(dir, packedName);
  const extractDir = path.join(dir, "pkg");
  fs.mkdirSync(extractDir, { recursive: true });
  try {
    // Windows only: forward-slash paths avoid MSYS mangling backslash
    // sequences in arguments, and --force-local stops GNU tar from reading
    // "C:/Users/..." as a "host:path" remote-archive spec (the drive letter
    // looks like a hostname prefix otherwise). Both are confirmed needed
    // together by testing — neither alone is sufficient. --force-local is a
    // GNU tar flag BSD tar (macOS's default) does not recognize, so this
    // must not run on other platforms.
    const isWin = process.platform === "win32";
    const toTarPath = (p: string) => (isWin ? p.replace(/\\/g, "/") : p);
    const tarArgs = isWin
      ? ["--force-local", "-xzf", toTarPath(tarballPath), "-C", toTarPath(extractDir)]
      : ["-xzf", tarballPath, "-C", extractDir];
    execFileSync("tar", tarArgs, { stdio: ["ignore", "ignore", "pipe"] });
  } catch (err) {
    cleanupDir(dir)();
    throw new Error(
      `Downloaded "${spec}" but could not extract the tarball (is "tar" on PATH?): ${(err as Error).message}`,
    );
  }

  // npm packs everything under a single "package/" directory.
  const inner = path.join(extractDir, "package");
  const resolvedDir = fs.existsSync(inner) ? inner : extractDir;

  let label = spec;
  try {
    const pkgJson = JSON.parse(fs.readFileSync(path.join(resolvedDir, "package.json"), "utf-8")) as {
      name?: string;
      version?: string;
    };
    if (pkgJson.name) label = `${pkgJson.name}@${pkgJson.version ?? "?"}`;
  } catch {
    /* fall back to the raw spec as the label */
  }

  return { dir: resolvedDir, kind: "npm", label, cleanup: cleanupDir(dir) };
}

export function resolveTarget(spec: string): ResolvedTarget {
  const kind = classify(spec);
  if (kind === "local") {
    const resolved = path.resolve(spec);
    return { dir: resolved, kind, label: resolved, cleanup: () => {} };
  }
  if (kind === "git") return fetchGit(spec);
  return fetchNpm(spec);
}
