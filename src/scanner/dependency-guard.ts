import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";
import { findAdvisories, type PackageAdvisory } from "./advisories.js";
import { findMcpConfigFiles, parseServers } from "./mcp-config-scanner.js";
import { parseExactVersion, versionSatisfiesRange } from "./semver.js";
import { evidenceConfidence } from "./confidence.js";
import { stripBom } from "../utils/text.js";

export interface DependencyGuardOptions {
  rootPath: string;
  checker?: PackageExistenceChecker;
}

interface PackageCandidate {
  ecosystem: "npm" | "pypi";
  name: string;
  file: string;
  line: number;
  /** Raw declared version spec, if one was present (e.g. "1.0.16", "^1.0.0", ">=0.1.16"). */
  version?: string;
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
        rule_id: "DEP001",
        title: "Dependency package not found in registry",
        severity: "medium",
        file: candidate.file,
        line: candidate.line,
        summary: `${candidate.name} was not found in ${candidate.ecosystem}.`,
        description:
          "The dependency name could be a typo, a hallucinated package (slopsquatting target), or a stale reference. If someone later publishes a package under this name, your install pulls their code.",
        recommendation:
          "Verify package spelling and replace with a known, maintained package before installation.",
        confidence: 0.9,
        evidence: "proven",
      });
      continue;
    }

    const target = looksLikeTyposquat(candidate.name);
    if (target) {
      findings.push({
        rule_id: "DEP002",
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
        evidence: "heuristic",
      });
    }
  }

  return findings;
}

/**
 * DEP003: dependencies with a documented malicious release or critical CVE.
 * Fully offline (curated incidents + a bundled OSV snapshot), so unlike the
 * registry checks above this runs on every scan, and additionally covers
 * packages launched from MCP configs (`npx -y some-server`).
 *
 * The two advisory kinds get deliberately different ambiguity handling:
 *
 * - `malicious` — an unresolvable version spec still flags. Installing a
 *   backdoored release is unrecoverable, so "unsure" must mean "keep the
 *   finding," never "clear it."
 * - `vulnerable` — a CVE only flags when the declared version is an exact pin
 *   provably inside the affected range. Applying the malicious-kind rule to
 *   the CVE snapshot would fire `proven` on every unpinned mainstream
 *   dependency (`langchain>=0.1`), which is precisely the noise this scanner
 *   exists to avoid. Unpinned-but-possibly-affected is surfaced at
 *   `heuristic` (--paranoid) instead.
 */
export function scanKnownMaliciousPackages(rootPath: string, skipPaths?: string[]): Finding[] {
  const candidates = [
    ...collectDependencyCandidates(rootPath),
    ...collectMcpConfigPackages(rootPath, skipPaths),
  ];

  const findings: Finding[] = [];
  for (const candidate of candidates) {
    const advisories = findAdvisories(candidate.ecosystem, candidate.name);
    if (advisories.length === 0) continue;

    const exact = candidate.version ? parseExactVersion(candidate.version) : undefined;

    const malicious: PackageAdvisory[] = [];
    const confirmed: PackageAdvisory[] = [];
    const unresolved: PackageAdvisory[] = [];

    for (const advisory of advisories) {
      const inRange = advisoryCoversVersion(advisory, exact);
      if (advisory.kind === "malicious") {
        if (inRange !== false) malicious.push(advisory);
      } else if (inRange === true) {
        confirmed.push(advisory);
      } else if (inRange === undefined) {
        unresolved.push(advisory);
      }
    }

    if (malicious.length > 0) {
      findings.push(
        advisoryFinding(candidate, malicious, "critical", "proven", {
          summary: `${candidate.name} has a documented malicious release${rangeSuffix(malicious[0])}.`,
          recommendation: `Remove ${candidate.name} immediately, rotate any credentials it could access, and review its activity. Reference: ${malicious[0].reference}`,
        }),
      );
      continue;
    }

    if (confirmed.length > 0) {
      findings.push(
        advisoryFinding(candidate, confirmed, "high", "proven", {
          summary: `${candidate.name}@${candidate.version} is inside the affected range of ${plural(confirmed.length, "advisory", "advisories")}.`,
          recommendation: `Update ${candidate.name} past the affected range (${confirmed[0].affectedVersions ?? "see reference"}). Reference: ${confirmed[0].reference}`,
        }),
      );
      continue;
    }

    if (unresolved.length > 0) {
      findings.push(
        advisoryFinding(candidate, unresolved, "medium", "heuristic", {
          summary: `${candidate.name} is declared as "${candidate.version ?? "unpinned"}", which cannot be proven outside ${plural(unresolved.length, "a known advisory range", "known advisory ranges")}.`,
          recommendation: `Pin ${candidate.name} to an exact version at or above the patched release so this can be verified. Reference: ${unresolved[0].reference}`,
        }),
      );
    }
  }
  return findings;
}

/**
 * Is `version` inside the advisory's affected range? `undefined` means
 * "can't tell" (no pinned version, or a range this scanner won't parse) and
 * is handled per-kind by the caller — never silently treated as "safe".
 */
function advisoryCoversVersion(
  advisory: PackageAdvisory,
  version: ReturnType<typeof parseExactVersion>,
): boolean | undefined {
  const ranges = advisory.ranges ?? (advisory.affectedVersions ? [advisory.affectedVersions] : []);
  if (ranges.length === 0) return true;
  if (!version) return undefined;

  let sawUnknown = false;
  for (const range of ranges) {
    const satisfies = versionSatisfiesRange(version, range);
    if (satisfies === true) return true;
    if (satisfies === undefined) sawUnknown = true;
  }
  return sawUnknown ? undefined : false;
}

function advisoryFinding(
  candidate: PackageCandidate,
  advisories: PackageAdvisory[],
  severity: Finding["severity"],
  evidence: Finding["evidence"],
  text: { summary: string; recommendation: string },
): Finding {
  const shown = advisories.slice(0, 3).map((a) => `• ${a.reason} (${a.reference})`);
  const more = advisories.length > shown.length ? `\n• …and ${advisories.length - shown.length} more.` : "";
  return {
    rule_id: "DEP003",
    title: "Dependency has a known-malicious or critically vulnerable release",
    severity,
    file: candidate.file,
    line: candidate.line,
    summary: text.summary,
    description: shown.join("\n") + more,
    recommendation: text.recommendation,
    confidence: evidenceConfidence(evidence),
    evidence,
  };
}

function rangeSuffix(advisory: PackageAdvisory): string {
  return advisory.affectedVersions ? ` (affected: ${advisory.affectedVersions})` : "";
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : `${n} ${many}`;
}

/** Package names launched by MCP config servers via npx/uvx-style runners. */
function collectMcpConfigPackages(rootPath: string, skipPaths?: string[]): PackageCandidate[] {
  const resolvedRoot = path.resolve(rootPath);
  const candidates: PackageCandidate[] = [];
  for (const configPath of findMcpConfigFiles(resolvedRoot, skipPaths)) {
    let raw: string;
    try {
      raw = fs.readFileSync(configPath, "utf-8");
    } catch {
      continue;
    }
    const { servers, lines } = parseServers(raw);
    const fileRelative = path.relative(resolvedRoot, configPath);
    for (const server of servers) {
      const command = (server.command ?? "").toLowerCase();
      const runner = command.split(/[\\/]/).pop() ?? "";
      const ecosystem = runner === "uvx" ? "pypi" : runner === "npx" || runner === "pnpx" || runner === "bunx" ? "npm" : undefined;
      if (!ecosystem) continue;
      const pkg = (server.args ?? []).find((a) => !a.startsWith("-"));
      if (!pkg) continue;
      // Split a version suffix: name@1.2.3 / @scope/name@1.2.3
      const at = pkg.lastIndexOf("@");
      const name = at > 0 ? pkg.slice(0, at) : pkg;
      const version = at > 0 ? pkg.slice(at + 1) : undefined;
      const lineIdx = lines.findIndex((l) => l.includes(pkg));
      candidates.push({ ecosystem, name, file: fileRelative, line: lineIdx >= 0 ? lineIdx + 1 : 1, version });
    }
  }
  return dedupeCandidates(candidates);
}

let warnedNetworkFailure = false;

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
      // Fail open (assume the package exists) so a transient network issue
      // can't manufacture a false "package not found" finding — but warn
      // once so a fully offline run doesn't silently no-op dependency
      // checking with no indication in the report.
      if (!warnedNetworkFailure) {
        warnedNetworkFailure = true;
        process.stderr.write(
          "Warning: could not reach package registry — dependency checks (DEP001) may be incomplete.\n",
        );
      }
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
    const raw = stripBom(fs.readFileSync(packageJsonPath, "utf-8"));
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
      for (const [name, version] of Object.entries(section)) {
        candidates.push({
          ecosystem: "npm",
          name,
          file: fileRelative,
          line: findLineNumber(fileText, `"${name}"`),
          version,
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
    const raw = stripBom(fs.readFileSync(requirementsPath, "utf-8"));
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
      // Keep the operator with the version. Stripping it turned every
      // `pkg>=1.2.3` / `pkg~=4.0` into what looked like an exact pin, so a
      // lower bound was compared against advisory ranges as though it were
      // the installed version — a proven-tier finding built on a version the
      // repo never actually declared. Only `==` is an exact pin.
      const versionMatch = line.match(/(===?|>=|<=|~=|!=|>|<)\s*([\w.*+!-]+)/);
      const version = versionMatch
        ? /^===?$/.test(versionMatch[1])
          ? versionMatch[2]
          : `${versionMatch[1]}${versionMatch[2]}`
        : undefined;
      candidates.push({
        ecosystem: "pypi",
        name: nameMatch[1],
        file: fileRelative,
        line: index + 1,
        version,
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
  // Scoped npm packages ("@scope/name") legitimately contain a slash;
  // rejecting it here previously short-circuited every scoped package
  // (e.g. @types/node) straight to a false "not found" DEP001 finding
  // before the registry was ever queried.
  return /^(@[a-zA-Z0-9._-]{1,213}\/)?[a-zA-Z0-9._-]{1,214}$/.test(name);
}
