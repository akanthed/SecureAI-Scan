import path from "node:path";
import { Project } from "ts-morph";

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

export function createScanProject(rootPath: string, skipPaths?: string[]): Project {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
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
