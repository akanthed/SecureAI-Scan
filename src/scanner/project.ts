import fs from "node:fs";
import path from "node:path";
import { Project, ts } from "ts-morph";

const DEFAULT_EXCLUDES = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/out/**",
  "**/.next/**",
];

// fast-glob (used internally by ts-morph's addSourceFilesAtPaths) treats `\`
// as a glob escape character, not a path separator. On Windows, path.join/
// path.resolve produce backslash-separated paths, which silently breaks
// every negated exclude pattern (`!...`) — the exclude simply matches
// nothing. Glob patterns must always use forward slashes regardless of OS.
function toGlobPath(p: string): string {
  return p.split(path.sep).join("/");
}

/**
 * Only the module-resolution settings from the scanned repo's root
 * tsconfig.json: `baseUrl`/`paths` aliases (`@/lib/openai`, `~/utils/x`).
 * Without them every aliased import is unresolved, and import-resolved rules
 * cannot follow a call into the file that defines it. Nothing else from the
 * target's config is trusted or applied.
 */
function rootModuleResolution(root: string): ts.CompilerOptions {
  const configPath = path.join(root, "tsconfig.json");
  if (!fs.existsSync(configPath)) return {};
  try {
    const read = ts.readConfigFile(configPath, ts.sys.readFile);
    const options = read.config?.compilerOptions;
    if (read.error || !options || typeof options !== "object") return {};
    const result: ts.CompilerOptions = {};
    if (options.paths && typeof options.paths === "object") {
      result.paths = options.paths;
      result.baseUrl = path.resolve(root, typeof options.baseUrl === "string" ? options.baseUrl : ".");
    } else if (typeof options.baseUrl === "string") {
      result.baseUrl = path.resolve(root, options.baseUrl);
    }
    return result;
  } catch {
    return {};
  }
}

export function createScanProject(rootPath: string, skipPaths?: string[]): Project {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    compilerOptions: rootModuleResolution(path.resolve(rootPath)),
  });

  const resolvedRoot = path.resolve(rootPath);
  const normalizedRoot = toGlobPath(resolvedRoot);
  const policyExcludes = (skipPaths ?? []).map(
    (p) => `!${toGlobPath(path.resolve(resolvedRoot, p))}`,
  );
  project.addSourceFilesAtPaths([
    `${normalizedRoot}/**/*.ts`,
    `${normalizedRoot}/**/*.tsx`,
    `${normalizedRoot}/**/*.js`,
    `${normalizedRoot}/**/*.jsx`,
    ...DEFAULT_EXCLUDES.map((pattern) => `!${normalizedRoot}/${pattern}`),
    ...policyExcludes,
  ]);

  return project;
}
