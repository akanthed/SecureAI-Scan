/**
 * Curated advisory list for AI/MCP packages with documented malicious releases
 * or critical vulnerabilities. Checked offline on every scan (DEP003) — unlike
 * the registry-existence checks (DEP001/DEP002), no network is needed.
 *
 * This file is hand-maintained and holds incidents OSV does not carry (yanked
 * malicious packages, in-the-wild backdoors). The much larger CVE half of
 * DEP003 lives in the generated snapshot — see scripts/sync-advisories.js.
 *
 * Inclusion bar: a public incident report or CVE. Do not add packages on
 * suspicion — this list produces `proven` findings. Maintenance process is
 * documented in CONTRIBUTING.md.
 */
import { GENERATED_ADVISORIES } from "./advisories-generated.js";

export interface PackageAdvisory {
  ecosystem: "npm" | "pypi";
  name: string;
  kind: "malicious" | "vulnerable";
  /** Human-readable affected range, e.g. ">=1.0.16" or "<0.1.16". */
  affectedVersions?: string;
  /**
   * Machine-comparable comparator strings, OR'd together. Present on
   * generated entries where an advisory spans several disjoint ranges;
   * `affectedVersions` alone can't express that.
   */
  ranges?: string[];
  reason: string;
  reference: string;
}

export const PACKAGE_ADVISORIES: PackageAdvisory[] = [
  {
    ecosystem: "npm",
    name: "postmark-mcp",
    kind: "malicious",
    affectedVersions: ">=1.0.16",
    reason:
      "Version 1.0.16 added a backdoor that BCC'd every outgoing email to an attacker-controlled address — the first documented in-the-wild malicious MCP server.",
    reference: "https://www.koi.security/blog/postmark-mcp-npm-malicious-backdoor",
  },
  {
    ecosystem: "npm",
    name: "mcp-remote",
    kind: "vulnerable",
    affectedVersions: "<0.1.16",
    reason:
      "CVE-2025-6514: a malicious MCP server URL could achieve remote command execution on the client machine when connecting.",
    reference: "https://nvd.nist.gov/vuln/detail/CVE-2025-6514",
  },
];

/** PEP 503 name normalization for PyPI; plain lowercase for npm. */
function normalizeName(ecosystem: "npm" | "pypi", name: string): string {
  const lower = name.toLowerCase();
  return ecosystem === "pypi" ? lower.replace(/[-_.]+/g, "-") : lower;
}

const ALL_ADVISORIES: PackageAdvisory[] = [...PACKAGE_ADVISORIES, ...GENERATED_ADVISORIES];

/** Every advisory affecting a package. Curated entries come first. */
export function findAdvisories(ecosystem: "npm" | "pypi", name: string): PackageAdvisory[] {
  const normalized = normalizeName(ecosystem, name);
  return ALL_ADVISORIES.filter(
    (a) => a.ecosystem === ecosystem && normalizeName(ecosystem, a.name) === normalized,
  );
}

export function findAdvisory(ecosystem: "npm" | "pypi", name: string): PackageAdvisory | undefined {
  return findAdvisories(ecosystem, name)[0];
}
