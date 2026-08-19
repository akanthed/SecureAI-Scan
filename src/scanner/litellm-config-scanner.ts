import fs from "node:fs";
import path from "node:path";
import { load as yamlLoad } from "js-yaml";
import type { Finding } from "./types.js";
import { evidenceConfidence, identifierTokens } from "./confidence.js";
import { stripBom } from "../utils/text.js";

/**
 * Scans LiteLLM proxy `config.yaml` files for parsed, factual
 * misconfigurations. Off-disk, not AST-based — same pattern as
 * mcp-config-scanner.ts.
 *
 * Rules:
 *   LLC001 — hardcoded secret in litellm_params/general_settings
 *   LLC002 — plaintext HTTP provider endpoint (non-localhost)
 *   LLC003 — no guardrails configured (heuristic, --paranoid only)
 */

const SKIP_DIRS = new Set([
  "node_modules",
  ".git",
  "dist",
  "build",
  "out",
  ".next",
  ".venv",
  "venv",
  "__pycache__",
]);

const YAML_EXTENSIONS = new Set([".yaml", ".yml"]);

export interface LiteLlmModelEntry {
  model_name?: string;
  litellm_params?: Record<string, unknown>;
}

export interface LiteLlmConfig {
  model_list: LiteLlmModelEntry[];
  general_settings?: Record<string, unknown>;
  hasGuardrails: boolean;
}

export function findLiteLlmConfigFiles(rootPath: string, skipPaths?: string[]): string[] {
  const results: string[] = [];
  const resolvedRoot = path.resolve(rootPath);
  const skips = (skipPaths ?? []).map((p) => path.resolve(resolvedRoot, p));

  function walk(dir: string, depth: number) {
    if (depth > 6) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (skips.some((s) => full === s || full.startsWith(s + path.sep))) continue;
      if (entry.isDirectory()) {
        if (SKIP_DIRS.has(entry.name)) continue;
        walk(full, depth + 1);
      } else if (entry.isFile()) {
        if (YAML_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
          results.push(full);
        }
      }
    }
  }

  walk(resolvedRoot, 0);
  return results;
}

/**
 * Structural gate: only treat a YAML file as a LiteLLM proxy config when it
 * has a top-level `model_list` array with at least one entry carrying a real
 * `litellm_params` object. This is LiteLLM's own proxy config shape and is
 * distinctive enough to avoid false-positiving on unrelated YAML (k8s config,
 * generic app config, etc). Anything that doesn't match is silently skipped.
 */
export function parseLiteLlmConfig(raw: string): LiteLlmConfig | null {
  let parsed: unknown;
  try {
    parsed = yamlLoad(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== "object" || parsed === null) return null;

  const obj = parsed as Record<string, unknown>;
  const rawModelList = obj.model_list;
  if (!Array.isArray(rawModelList)) return null;

  const modelList: LiteLlmModelEntry[] = [];
  let hasLitellmParams = false;
  for (const rawEntry of rawModelList) {
    if (typeof rawEntry !== "object" || rawEntry === null) continue;
    const entry = rawEntry as Record<string, unknown>;
    const litellmParams =
      typeof entry.litellm_params === "object" && entry.litellm_params !== null
        ? (entry.litellm_params as Record<string, unknown>)
        : undefined;
    if (litellmParams) hasLitellmParams = true;
    modelList.push({
      model_name: typeof entry.model_name === "string" ? entry.model_name : undefined,
      litellm_params: litellmParams,
    });
  }

  if (!hasLitellmParams) return null;

  const generalSettings =
    typeof obj.general_settings === "object" && obj.general_settings !== null
      ? (obj.general_settings as Record<string, unknown>)
      : undefined;

  // guardrails can live top-level or nested under litellm_settings.
  const litellmSettings =
    typeof obj.litellm_settings === "object" && obj.litellm_settings !== null
      ? (obj.litellm_settings as Record<string, unknown>)
      : undefined;
  const hasGuardrails =
    "guardrails" in obj || (litellmSettings !== undefined && "guardrails" in litellmSettings);

  return { model_list: modelList, general_settings: generalSettings, hasGuardrails };
}

/** Find the 1-based line where a string first appears, for report anchoring. */
function lineOf(lines: string[], needle: string): number {
  const idx = lines.findIndex((l) => l.includes(needle));
  return idx >= 0 ? idx + 1 : 1;
}

// Known LiteLLM credential fields — api_key/master_key/salt_key are documented
// top-level litellm_params/general_settings fields; the suffix pattern covers
// bundled integration credentials (Langfuse, Aporia, etc.) that follow the
// same *_api_key/*_key/*_token naming convention.
const CREDENTIAL_FIELD = /(^api_key$|^master_key$|^salt_key$|(_api_key|_key|_token)$)/i;
const ENV_REFERENCE = /^os\.environ\//;

// LiteLLM's own docs/tests inline placeholder values like "fake-key",
// "my-fake-key", "sk-lar1-demo" to demonstrate config shape — not real
// secrets. Found scanning BerriAI/litellm itself (regression). A value built
// entirely from ordinary placeholder words, with no other content, isn't
// evidence of a leaked credential.
const PLACEHOLDER_TOKENS = new Set([
  "fake",
  "dummy",
  "test",
  "tests",
  "demo",
  "sample",
  "example",
  "examples",
  "placeholder",
  "changeme",
  "todo",
  "tbd",
  "xxx",
  "redacted",
  "mock",
  "stub",
  "insert",
  "notreal",
  "your",
]);

function isPlaceholderValue(value: string): boolean {
  const tokens = identifierTokens(value);
  if (tokens.length > 0 && tokens.every((t) => PLACEHOLDER_TOKENS.has(t))) return true;

  // Real credentials are one long, effectively random alphanumeric run
  // (sometimes with a short vendor prefix like "sk-"/"AKIA" split off by a
  // hyphen). Hyphen/underscore-joined human phrases — "sk-lar1-demo" — never
  // produce a long unbroken run even when no individual word is on the deny
  // list above. Below this length, treat it as not credential-shaped.
  const runs = value.match(/[A-Za-z0-9]+/g) ?? [];
  const longestRun = Math.max(0, ...runs.map((r) => r.length));
  return longestRun < 12;
}

function isLiteralSecret(key: string, value: unknown): value is string {
  if (typeof value !== "string") return false;
  if (!CREDENTIAL_FIELD.test(key)) return false;
  const trimmed = value.trim();
  if (trimmed.length < 8) return false;
  if (ENV_REFERENCE.test(trimmed)) return false;
  if (isPlaceholderValue(trimmed)) return false;
  return true;
}

export function scanLiteLlmConfigs(rootPath: string, skipPaths?: string[]): Finding[] {
  const findings: Finding[] = [];
  const resolvedRoot = path.resolve(rootPath);

  for (const configPath of findLiteLlmConfigFiles(resolvedRoot, skipPaths)) {
    let raw: string;
    try {
      raw = stripBom(fs.readFileSync(configPath, "utf-8"));
    } catch {
      continue;
    }
    const relFile = path.relative(resolvedRoot, configPath);
    const config = parseLiteLlmConfig(raw);
    if (!config) continue;
    const lines = raw.split(/\r?\n/);

    const credentialBlocks: Array<{ label: string; block: Record<string, unknown> | undefined }> = [
      ...config.model_list.map((entry, i) => ({
        label: entry.model_name ?? `model_list[${i}]`,
        block: entry.litellm_params,
      })),
      { label: "general_settings", block: config.general_settings },
    ];

    for (const { label, block } of credentialBlocks) {
      if (!block) continue;

      // LLC001 — hardcoded secret
      for (const [key, value] of Object.entries(block)) {
        if (!isLiteralSecret(key, value)) continue;
        findings.push({
          rule_id: "LLC001",
          title: "Hardcoded secret in LiteLLM config",
          severity: "critical",
          file: relFile,
          // Search by the literal value, not the key: key names like "api_key"
          // repeat across every model_list entry, so a key-only search can
          // anchor the finding to an unrelated (possibly safe) line with the
          // same key. The flagged value itself is what's unique.
          line: lineOf(lines, value),
          summary: `"${label}" has a literal value for "${key}" instead of an os.environ/ reference.`,
          description:
            "LiteLLM proxy config files are routinely committed and shared across a team. A credential written directly into the config, rather than referenced via LiteLLM's os.environ/VAR_NAME convention, is exposed to everyone with repo access and to any process that reads the file.",
          recommendation: `Reference the environment instead of inlining the value, e.g. "${key}": "os.environ/${key.toUpperCase()}", and rotate the exposed credential now.`,
          confidence: evidenceConfidence("proven"),
          evidence: "proven",
        });
      }

      // LLC002 — plaintext HTTP endpoint
      const apiBase = block.api_base;
      if (typeof apiBase === "string" && /^http:\/\//i.test(apiBase)) {
        const host = apiBase.replace(/^http:\/\//i, "").split(/[/:]/)[0].toLowerCase();
        const isLocal = host === "localhost" || host === "127.0.0.1" || host === "0.0.0.0" || host === "::1";
        if (!isLocal) {
          findings.push({
            rule_id: "LLC002",
            title: "Plaintext HTTP provider endpoint",
            severity: "high",
            file: relFile,
            line: lineOf(lines, apiBase),
            summary: `"${label}" reaches ${apiBase} without TLS.`,
            description:
              "Requests and responses — including API keys sent as headers and prompt/completion content — travel unencrypted. An on-path attacker can read the traffic or tamper with it.",
            recommendation: "Use https:// for all non-localhost provider api_base URLs.",
            confidence: evidenceConfidence("proven"),
            evidence: "proven",
          });
        }
      }
    }

    // LLC003 — no guardrails configured (heuristic: absence is only a nudge)
    if (!config.hasGuardrails) {
      findings.push({
        rule_id: "LLC003",
        title: "No guardrails configured",
        severity: "low",
        file: relFile,
        line: 1,
        summary: "LiteLLM proxy config has no guardrails: section.",
        description:
          "This config defines model routing but no guardrails. Absence of an optional feature is not itself a vulnerability — this is a nudge, not a proven gap — but LiteLLM Proxy supports pre/post-call guardrails for PII, prompt injection, and content moderation that this config isn't using.",
        recommendation:
          "Consider adding a guardrails: section (top-level or under litellm_settings) if this proxy handles untrusted input.",
        confidence: evidenceConfidence("heuristic"),
        evidence: "heuristic",
      });
    }
  }

  return findings;
}
