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
  /**
   * For `malicious` entries whose bad releases are a closed, enumerated set
   * (a worm that published a few versions of an otherwise legitimate package).
   * Only an exact pin inside the range fires `proven`; an unresolved spec like
   * `^2.0.0` drops to `heuristic`, because it may well resolve to a clean release.
   * Leave unset for backdoors where every later version is the attacker's.
   */
  exactOnly?: boolean;
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
  {
    ecosystem: "npm",
    name: "@lanyer640/mcp-runcommand-server",
    kind: "malicious",
    affectedVersions: ">=1.0.6",
    reason:
      "Version 1.0.6 replaced run_command with a reverse shell that dials a hard-coded attacker IP on install/startup. Package was removed from npm after disclosure.",
    reference:
      "https://www.geordie.ai/resources/security-advisory-remote-shell-backdoor-in-mcp-package-lanyer640-mcp-runcommand-server",
  },
  // Mini Shai-Hulud (TeamPCP worm, May 2026). Each package below is a legitimate
  // project whose maintainer credentials were stolen; only the enumerated
  // releases are malicious, hence exactOnly. Version lists: Wiz's affected-package table.
  ...miniShaiHulud("pypi", "guardrails-ai", "=0.10.1", "0.10.1"),
  ...miniShaiHulud("pypi", "mistralai", "=2.4.6", "2.4.6"),
  ...miniShaiHulud("npm", "@mistralai/mistralai", ">=2.2.2 <=2.2.4", "2.2.2-2.2.4"),
  ...miniShaiHulud("npm", "@mistralai/mistralai-azure", ">=1.7.1 <=1.7.3", "1.7.1-1.7.3"),
  ...miniShaiHulud("npm", "@mistralai/mistralai-gcp", ">=1.7.1 <=1.7.3", "1.7.1-1.7.3"),
  ...miniShaiHulud("npm", "cmux-agent-mcp", ">=0.1.3 <=0.1.8", "0.1.3-0.1.8"),
  ...miniShaiHulud("npm", "nextmove-mcp", ">=0.1.3 <=0.1.7", "0.1.3-0.1.7"),
  ...miniShaiHulud("npm", "@squawk/mcp", ">=0.9.1 <=0.9.5", "0.9.1-0.9.5"),
  ...miniShaiHulud("npm", "@dirigible-ai/sdk", ">=0.6.2 <=0.6.3", "0.6.2-0.6.3"),
  ...miniShaiHulud("npm", "agentwork-cli", ">=0.1.4 <=0.1.5", "0.1.4-0.1.5"),
  ...miniShaiHulud("npm", "@uipath/agent-sdk", "=1.0.2", "1.0.2"),
  ...miniShaiHulud("npm", "@uipath/agent.sdk", "=0.0.18", "0.0.18"),
  ...miniShaiHulud("npm", "@uipath/agent-tool", "=1.0.1", "1.0.1"),
  ...miniShaiHulud("npm", "@uipath/llmgw-tool", "=1.0.1", "1.0.1"),
  ...miniShaiHulud("npm", "@uipath/context-grounding-tool", "=0.1.1", "0.1.1"),
  {
    // Mastra npm compromise (Sapphire Sleet, 2026-06-17). Injected into 140+ @mastra/*
    // releases as a phantom dependency. No per-release list exists, so the Mastra
    // packages themselves are deliberately not listed; this catches the dropper.
    ecosystem: "npm",
    name: "easy-day-js",
    kind: "malicious",
    reason:
      "Typosquat of dayjs published by the attacker. Version 1.11.22 carries a postinstall dropper; it was injected as a dependency into compromised @mastra/* releases.",
    reference: "https://www.stepsecurity.io/blog/mastra-npm-packages-compromised-using-easy-day-js",
  },
];

function miniShaiHulud(
  ecosystem: "npm" | "pypi",
  name: string,
  range: string,
  versions: string,
): PackageAdvisory[] {
  return [
    {
      ecosystem,
      name,
      kind: "malicious",
      affectedVersions: range,
      exactOnly: true,
      reason: `Release ${versions} was published by the Mini Shai-Hulud worm and steals credentials on ${ecosystem === "pypi" ? "import" : "install"}. Other releases are not affected.`,
      reference: "https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised",
    },
  ];
}

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
