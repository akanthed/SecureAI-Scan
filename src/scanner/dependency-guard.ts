import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";

export interface DependencyGuardOptions {
  rootPath: string;
  checker?: PackageExistenceChecker;
}

interface PackageCandidate {
  ecosystem: "npm" | "pypi";
  name: string;
  file: string;
  line: number;
}

export interface PackageExistenceChecker {
  exists(ecosystem: "npm" | "pypi", name: string): Promise<boolean>;
}

const TRUSTED_PACKAGE_NAMES = [
  "openai",
  "anthropic",
  "langchain",
  "llamaindex",
  "transformers",
  "requests",
  "numpy",
  "pandas",
  "torch",
  "fastapi",
  "django",
  "flask",
];

export async function scanDependencyFilesForRisks(
  options: DependencyGuardOptions,
): Promise<Finding[]> {
  const checker = options.checker ?? new RegistryExistenceChecker();
  const candidates = collectDependencyCandidates(options.rootPath);
  const findings: Finding[] = [];

  for (const candidate of candidates) {
    const exists = await checker.exists(candidate.ecosystem, candidate.name);
    if (!exists) {
      findings.push({
        rule_id: "LLM_DEP001",
        title: "Dependency package not found in registry",
        severity: "low",
        file: candidate.file,
        line: candidate.line,
        summary: `${candidate.name} was not found in ${candidate.ecosystem}.`,
        description:
          "The dependency name could be a typo, hallucinated package, or stale reference.",
        recommendation:
          "Verify package spelling and replace with a known, maintained package before installation.",
        confidence: 0.9,
      });
      continue;
    }

    const target = looksLikeTyposquat(candidate.name);
    if (target) {
      findings.push({
        rule_id: "LLM_DEP002",
        title: "Dependency name looks similar to a popular package",
        severity: "low",
        file: candidate.file,
        line: candidate.line,
        summary: `${candidate.name} may be confused with ${target}.`,
        description:
          "Similar package names can indicate typosquatting or accidental confusion in dependency selection.",
        recommendation:
          "Confirm package ownership and intended source before installing in production.",
        confidence: 0.6,
      });
    }
  }

  return findings;
}

class RegistryExistenceChecker implements PackageExistenceChecker {
  async exists(ecosystem: "npm" | "pypi", name: string): Promise<boolean> {
    if (!isReasonablePackageName(name)) {
      return false;
    }
    const endpoint =
      ecosystem === "npm"
        ? `https://registry.npmjs.org/${encodeURIComponent(name)}`
        : `https://pypi.org/pypi/${encodeURIComponent(name)}/json`;

    try {
      const response = await fetch(endpoint, {
        method: "GET",
        headers: { "user-agent": "secureai-scan/0.x" },
      });
      return response.ok;
    } catch {
      return true;
    }
  }
}

function collectDependencyCandidates(rootPath: string): PackageCandidate[] {
  const resolvedRoot = path.resolve(rootPath);
  const candidates: PackageCandidate[] = [];

  const packageJsonPath = path.join(resolvedRoot, "package.json");
  if (fs.existsSync(packageJsonPath)) {
    candidates.push(...readNpmCandidates(packageJsonPath, resolvedRoot));
  }

  const requirementsPath = path.join(resolvedRoot, "requirements.txt");
  if (fs.existsSync(requirementsPath)) {
    candidates.push(...readRequirementsCandidates(requirementsPath, resolvedRoot));
  }

  return dedupeCandidates(candidates);
}

function readNpmCandidates(packageJsonPath: string, rootPath: string): PackageCandidate[] {
  try {
    const raw = fs.readFileSync(packageJsonPath, "utf-8");
    const parsed = JSON.parse(raw) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    const sections = [
      parsed.dependencies ?? {},
      parsed.devDependencies ?? {},
      parsed.peerDependencies ?? {},
      parsed.optionalDependencies ?? {},
    ];
    const fileText = raw.split(/\r?\n/);
    const fileRelative = path.relative(rootPath, packageJsonPath);
    const candidates: PackageCandidate[] = [];
    for (const section of sections) {
      for (const name of Object.keys(section)) {
        candidates.push({
          ecosystem: "npm",
          name,
          file: fileRelative,
          line: findLineNumber(fileText, `"${name}"`),
        });
      }
    }
    return candidates;
  } catch {
    return [];
  }
}

function readRequirementsCandidates(requirementsPath: string, rootPath: string): PackageCandidate[] {
  try {
    const raw = fs.readFileSync(requirementsPath, "utf-8");
    const lines = raw.split(/\r?\n/);
    const fileRelative = path.relative(rootPath, requirementsPath);
    const candidates: PackageCandidate[] = [];

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index].trim();
      if (
        line.length === 0 ||
        line.startsWith("#") ||
        line.startsWith("-") ||
        line.includes("://")
      ) {
        continue;
      }
      const nameMatch = line.match(/^([A-Za-z0-9_.-]+)/);
      if (!nameMatch) {
        continue;
      }
      candidates.push({
        ecosystem: "pypi",
        name: nameMatch[1],
        file: fileRelative,
        line: index + 1,
      });
    }

    return candidates;
  } catch {
    return [];
  }
}

function findLineNumber(lines: string[], needle: string): number {
  const index = lines.findIndex((line) => line.includes(needle));
  return index === -1 ? 1 : index + 1;
}

function dedupeCandidates(candidates: PackageCandidate[]): PackageCandidate[] {
  const seen = new Set<string>();
  const unique: PackageCandidate[] = [];
  for (const candidate of candidates) {
    const key = `${candidate.ecosystem}|${candidate.name.toLowerCase()}|${candidate.file}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    unique.push(candidate);
  }
  return unique;
}

function looksLikeTyposquat(name: string): string | undefined {
  const normalized = name.toLowerCase();
  if (TRUSTED_PACKAGE_NAMES.includes(normalized)) {
    return undefined;
  }
  for (const trusted of TRUSTED_PACKAGE_NAMES) {
    if (editDistance(normalized, trusted) === 1) {
      return trusted;
    }
  }
  return undefined;
}

function editDistance(a: string, b: string): number {
  if (a === b) {
    return 0;
  }
  if (Math.abs(a.length - b.length) > 1) {
    return 2;
  }

  const dp: number[][] = Array.from({ length: a.length + 1 }, () =>
    Array.from({ length: b.length + 1 }, () => 0),
  );
  for (let i = 0; i <= a.length; i += 1) {
    dp[i][0] = i;
  }
  for (let j = 0; j <= b.length; j += 1) {
    dp[0][j] = j;
  }
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost,
      );
    }
  }
  return dp[a.length][b.length];
}

function isReasonablePackageName(name: string): boolean {
  return /^[a-zA-Z0-9@._-]{1,214}$/.test(name);
}
