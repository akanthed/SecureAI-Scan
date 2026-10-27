import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
export const root = path.resolve(here, "..", "..");

// Bump when checkout settings change so stale caches are re-fetched.
const CACHE_VERSION = "v2-autocrlf-false";

export class PatchError extends Error {}

const git = (args, cwd) => execFileSync("git", args, { cwd, stdio: ["ignore", "pipe", "pipe"], encoding: "utf-8" });

/** Shallow-fetches exactly `sha` into <cacheDir>/<repo>-<sha7>; reuses a completed checkout. */
export function checkoutAt(repoUrl, sha, cacheDir) {
  const name = path.basename(repoUrl, ".git");
  const dest = path.join(cacheDir, `${name}-${sha.slice(0, 7)}`);
  const marker = path.join(dest, ".corpus-ok");
  if (fs.existsSync(marker) && fs.readFileSync(marker, "utf-8") === CACHE_VERSION) return dest;
  fs.rmSync(dest, { recursive: true, force: true });
  fs.mkdirSync(dest, { recursive: true });
  try {
    git(["init", "-q"], dest);
    git(["config", "core.autocrlf", "false"], dest); // keep patches byte-identical across OSes
    git(["remote", "add", "origin", repoUrl], dest);
    git(["fetch", "-q", "--depth", "1", "origin", sha], dest);
    git(["-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], dest);
  } catch (err) {
    throw new Error(`cannot fetch ${repoUrl} @ ${sha}: ${String(err.stderr ?? err.message).trim()}`);
  }
  const head = git(["rev-parse", "HEAD"], dest).trim();
  if (head !== sha) throw new Error(`checkout of ${repoUrl} resolved ${head}, expected ${sha}`);
  fs.writeFileSync(marker, CACHE_VERSION);
  return dest;
}

/** Copies a checkout to a scratch dir so a patch never dirties the cache. */
export function cloneForPatch(src) {
  const dest = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-corpus-"));
  fs.cpSync(src, dest, { recursive: true });
  return dest;
}

export function applyPatch(worktree, patchPath) {
  try {
    git(["apply", "--whitespace=nowarn", path.resolve(patchPath)], worktree);
  } catch (err) {
    throw new PatchError(`patch ${path.basename(patchPath)} failed to apply: ${String(err.stderr ?? err.message).trim()}`);
  }
}

/** Runs the built CLI (or `scannerCmd` with {dir}/{out}) and flattens findings. ok=false means no report was written. */
export function scanDir(dir, scannerCmd) {
  const out = path.join(os.tmpdir(), `secureai-corpus-${process.pid}-${Date.now()}.json`);
  try {
    if (scannerCmd) {
      execFileSync(scannerCmd.split("{dir}").join(dir).split("{out}").join(out), { shell: true, stdio: "ignore", maxBuffer: 1 << 26 });
    } else {
      execFileSync(process.execPath, [path.join(root, "dist", "index.js"), "scan", dir, "--output", out], { stdio: "ignore", maxBuffer: 1 << 26 });
    }
  } catch {
    // a non-zero exit with a written report is still usable; a missing report is handled below
  }
  if (!fs.existsSync(out)) return { ok: false, findings: [] };
  const report = JSON.parse(fs.readFileSync(out, "utf-8").replace(/^﻿/, ""));
  fs.rmSync(out, { force: true });
  const findings = [];
  for (const group of report.groups ?? []) {
    for (const o of group.occurrences ?? []) {
      findings.push({ ruleId: group.ruleId, file: String(o.file).replace(/\\/g, "/"), line: o.line, evidence: o.evidence });
    }
  }
  return { ok: true, findings };
}

/** Count of proven/likely findings for `rule` (heuristic never counts), optionally limited to `file`. */
export function hits(findings, { rule, file }) {
  const want = file?.replace(/\\/g, "/");
  return findings.filter(
    (f) => f.ruleId === rule && (f.evidence === "proven" || f.evidence === "likely") && (!want || f.file.endsWith(want)),
  ).length;
}
