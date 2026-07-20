/**
 * Curated advisory list for AI/MCP packages with documented malicious releases
 * or critical vulnerabilities. Checked offline on every scan (DEP003) — unlike
 * the registry-existence checks (DEP001/DEP002), no network is needed.
 *
 * Inclusion bar: a public incident report or CVE. Do not add packages on
 * suspicion — this list produces `proven` findings. Maintenance process is
 * documented in CONTRIBUTING.md.
 */

export interface PackageAdvisory {
  ecosystem: "npm" | "pypi";
  name: string;
  kind: "malicious" | "vulnerable";
  /** Human-readable affected range, e.g. ">=1.0.16" or "<0.1.16". */
  affectedVersions?: string;
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

export function findAdvisory(ecosystem: "npm" | "pypi", name: string): PackageAdvisory | undefined {
  const normalized = name.toLowerCase();
  return PACKAGE_ADVISORIES.find((a) => a.ecosystem === ecosystem && a.name === normalized);
}
