import fs from "node:fs";
import path from "node:path";
import type { Severity } from "./types.js";

export interface SecureAiPolicy {
  minSeverity?: Severity;
  minConfidence?: number;
  failOnSeverity?: Severity;
  skipPaths?: string[];
  onlyRules?: string[];
  blockedRules?: string[];
  maxLlmTokenLimit?: number;
  requireOutputValidation?: boolean;
}

export interface PolicyResult {
  policy: SecureAiPolicy;
  policyPath: string;
}

const POLICY_FILE_NAMES = [".secureai-policy.json", "secureai-policy.json"];

export function loadPolicy(rootPath: string): PolicyResult | undefined {
  for (const fileName of POLICY_FILE_NAMES) {
    const candidate = path.join(path.resolve(rootPath), fileName);
    if (!fs.existsSync(candidate)) continue;

    let raw: string;
    try {
      raw = fs.readFileSync(candidate, "utf-8");
    } catch {
      continue;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error(`Invalid JSON in policy file: ${candidate}`);
    }

    const policy = validatePolicy(parsed, candidate);
    return { policy, policyPath: candidate };
  }
  return undefined;
}

function validatePolicy(raw: unknown, filePath: string): SecureAiPolicy {
  if (typeof raw !== "object" || raw === null) {
    throw new Error(`Policy file must be a JSON object: ${filePath}`);
  }

  const obj = raw as Record<string, unknown>;
  const policy: SecureAiPolicy = {};
  const validSeverities: Severity[] = ["low", "medium", "high", "critical"];

  if (obj.minSeverity !== undefined) {
    if (!validSeverities.includes(obj.minSeverity as Severity)) {
      throw new Error(`policy.minSeverity must be one of: ${validSeverities.join(", ")}`);
    }
    policy.minSeverity = obj.minSeverity as Severity;
  }

  if (obj.failOnSeverity !== undefined) {
    if (!validSeverities.includes(obj.failOnSeverity as Severity)) {
      throw new Error(`policy.failOnSeverity must be one of: ${validSeverities.join(", ")}`);
    }
    policy.failOnSeverity = obj.failOnSeverity as Severity;
  }

  if (obj.minConfidence !== undefined) {
    const c = Number(obj.minConfidence);
    if (Number.isNaN(c) || c < 0 || c > 1) {
      throw new Error("policy.minConfidence must be a number between 0 and 1");
    }
    policy.minConfidence = c;
  }

  if (obj.skipPaths !== undefined) {
    if (!Array.isArray(obj.skipPaths) || !obj.skipPaths.every((p) => typeof p === "string")) {
      throw new Error("policy.skipPaths must be an array of strings");
    }
    policy.skipPaths = obj.skipPaths as string[];
  }

  if (obj.onlyRules !== undefined) {
    if (!Array.isArray(obj.onlyRules) || !obj.onlyRules.every((r) => typeof r === "string")) {
      throw new Error("policy.onlyRules must be an array of rule ID strings");
    }
    policy.onlyRules = obj.onlyRules as string[];
  }

  if (obj.blockedRules !== undefined) {
    if (!Array.isArray(obj.blockedRules) || !obj.blockedRules.every((r) => typeof r === "string")) {
      throw new Error("policy.blockedRules must be an array of rule ID strings");
    }
    policy.blockedRules = obj.blockedRules as string[];
  }

  if (obj.maxLlmTokenLimit !== undefined) {
    const t = Number(obj.maxLlmTokenLimit);
    if (Number.isNaN(t) || t < 1) {
      throw new Error("policy.maxLlmTokenLimit must be a positive number");
    }
    policy.maxLlmTokenLimit = t;
  }

  if (obj.requireOutputValidation !== undefined) {
    policy.requireOutputValidation = Boolean(obj.requireOutputValidation);
  }

  return policy;
}

const DEFAULT_POLICY_CONTENT = `{
  "$comment": "SecureAI-Scan policy file — commit this to your repo. See: secureai-scan explain <RULE_ID>",
  "minSeverity": "medium",
  "minConfidence": 0.45,
  "failOnSeverity": "high",
  "skipPaths": [],
  "blockedRules": [],
  "onlyRules": [],
  "requireOutputValidation": true
}
`;

export function writeDefaultPolicy(rootPath: string): string {
  const filePath = path.join(path.resolve(rootPath), ".secureai-policy.json");
  fs.writeFileSync(filePath, DEFAULT_POLICY_CONTENT, "utf-8");
  return filePath;
}

const DEFAULT_GITHUB_WORKFLOW = `name: SecureAI-Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  secureai-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22"
      - name: Install secureai-scan
        run: npm install -g secureai-scan
      - name: Run security scan
        run: |
          secureai-scan scan . \\
            --policy .secureai-policy.json \\
            --output secureai-report.html \\
            --baseline .secureai-baseline.json
      - name: Upload report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: secureai-report
          path: secureai-report.html
`;

export function writeGithubWorkflow(rootPath: string): string {
  const workflowDir = path.join(path.resolve(rootPath), ".github", "workflows");
  const workflowPath = path.join(workflowDir, "secureai-scan.yml");
  fs.mkdirSync(workflowDir, { recursive: true });
  fs.writeFileSync(workflowPath, DEFAULT_GITHUB_WORKFLOW, "utf-8");
  return workflowPath;
}
