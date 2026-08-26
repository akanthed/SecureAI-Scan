#!/usr/bin/env node
/**
 * Entry point for the pre-commit (https://pre-commit.com) hook declared in
 * `.pre-commit-hooks.yaml`.
 *
 * pre-commit's `language: node` installs this repo's package.json into an
 * isolated, cached node_modules — but that install is a bare `npm install`,
 * which does not run this project's own build (the published npm tarball
 * ships prebuilt `dist/`, but a git checkout of this repo does not, and
 * `dist/` is gitignored). There is no npm lifecycle script that reliably
 * builds on a plain `npm install` without also risking breaking the
 * published package for ordinary end users (a `postinstall` build would run
 * unconditionally, including against the registry tarball, which ships no
 * `src/`/`tsconfig.json` to build from). So this script builds explicitly,
 * once, in the cached checkout, then runs the scan against the consuming
 * project's working directory — cheap on every run after the first, since
 * pre-commit reuses the same cached checkout across commits for a given rev.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const useShell = process.platform === "win32";

const build = spawnSync("npm", ["run", "build", "--silent"], {
  cwd: repoRoot,
  stdio: "inherit",
  shell: useShell,
});
if (build.status !== 0) {
  process.exit(build.status ?? 1);
}

const scan = spawnSync(
  "node",
  [path.join(repoRoot, "dist", "index.js"), "scan", ".", ...process.argv.slice(2)],
  { cwd: process.cwd(), stdio: "inherit" },
);
process.exit(scan.status ?? 1);
