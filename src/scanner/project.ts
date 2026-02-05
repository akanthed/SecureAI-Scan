import path from "node:path";
import { Project } from "ts-morph";

const DEFAULT_EXCLUDES = [
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/out/**",
  "**/.next/**",
];

export function createScanProject(rootPath: string): Project {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
  });

  const normalizedRoot = path.resolve(rootPath);
  project.addSourceFilesAtPaths([
    path.join(normalizedRoot, "**/*.ts"),
    path.join(normalizedRoot, "**/*.tsx"),
    path.join(normalizedRoot, "**/*.js"),
    path.join(normalizedRoot, "**/*.jsx"),
    ...DEFAULT_EXCLUDES.map((pattern) => `!${path.join(normalizedRoot, pattern)}`),
  ]);

  return project;
}
