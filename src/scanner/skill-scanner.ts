import fs from "node:fs";
import path from "node:path";
import type { Finding } from "./types.js";
import { evidenceConfidence } from "./confidence.js";
import {
  findCrossToolReference,
  findInvisibleUnicode,
  matchInjectionPhrases,
} from "./tool-poisoning-checks.js";

/**
 * Scans Agent Skill files (SKILL.md — Claude Skills and equivalents) for the
 * same tool-poisoning shapes already detected in MCP tool metadata
 * (MCP007–MCP009): a skill's frontmatter description is always loaded into
 * the agent's context, and its body loads in full whenever the skill fires,
 * so both are trusted content an attacker can weaponize exactly like an MCP
 * tool description.
 *
 * Rules:
 *   SKL001 — invisible/bidi Unicode in a skill's frontmatter or body
 *   SKL002 — agent-directed injection phrasing in a skill's frontmatter or body
 *   SKL003 — a skill's content steers when/how a different skill is used
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

export function findSkillFiles(rootPath: string, skipPaths?: string[]): string[] {
  const results: string[] = [];
  const resolvedRoot = path.resolve(rootPath);
  const skips = (skipPaths ?? []).map((p) => path.resolve(resolvedRoot, p));

  function walk(dir: string, depth: number) {
    if (depth > 10) return;
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
      } else if (entry.isFile() && entry.name === "SKILL.md") {
        results.push(full);
      }
    }
  }

  walk(resolvedRoot, 0);
  return results;
}

export interface ParsedSkill {
  name: string;
  description?: string;
  /** 1-based line of the `description:` frontmatter field, if present. */
  descriptionLine: number;
  body: string;
  /** 1-based line where the body starts (first line after closing `---`). */
  bodyStartLine: number;
}

/**
 * Minimal frontmatter parser: `--- key: value ... ---` followed by the
 * markdown body. Deliberately hand-rolled rather than pulling in a YAML
 * dependency — skill frontmatter is a flat list of single-line string
 * fields, and this project keeps its dependency surface small.
 */
export function parseSkillFile(raw: string): ParsedSkill {
  const lines = raw.split(/\r?\n/);

  if (lines[0]?.trim() !== "---") {
    return { name: "", description: undefined, descriptionLine: 1, body: raw, bodyStartLine: 1 };
  }

  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "---") {
      end = i;
      break;
    }
  }
  if (end === -1) {
    return { name: "", description: undefined, descriptionLine: 1, body: raw, bodyStartLine: 1 };
  }

  let name = "";
  let description: string | undefined;
  let descriptionLine = 1;

  for (let i = 1; i < end; i++) {
    const match = lines[i].match(/^([A-Za-z0-9_-]+)\s*:\s*(.*)$/);
    if (!match) continue;
    const key = match[1].toLowerCase();
    const value = match[2].trim().replace(/^["'](.*)["']$/, "$1");
    if (key === "name") name = value;
    if (key === "description") {
      description = value;
      descriptionLine = i + 1;
    }
  }

  const bodyStartLine = end + 2;
  const body = lines.slice(end + 1).join("\n");
  return { name, description, descriptionLine, body, bodyStartLine };
}

/** 1-based line number of a character index within `text`, offset by `baseLine` (the 1-based line `text` starts on). */
function lineForIndex(text: string, index: number, baseLine: number): number {
  let line = baseLine;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/** First 1-based line at/after `baseLine` containing `needle`, or `baseLine` if not found. */
function lineOfSubstring(text: string, needle: string, baseLine: number): number {
  const idx = text.indexOf(needle);
  if (idx === -1) return baseLine;
  return lineForIndex(text, idx, baseLine);
}

/**
 * matchInjectionPhrases reports labels for a whole segment, not a position.
 * To anchor a finding at the actual matched line (segments can be a
 * multi-line skill body), re-run the same matcher per line and return the
 * first line that reproduces one of the given labels.
 */
function anchorLineForLabels(text: string, baseLine: number, labels: string[]): number {
  if (labels.length === 0) return baseLine;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const lineMatches = matchInjectionPhrases(lines[i]);
    const combined = [...lineMatches.strong, ...lineMatches.weak];
    if (combined.some((label) => labels.includes(label))) return baseLine + i;
  }
  return baseLine;
}

export function scanSkillFiles(rootPath: string, skipPaths?: string[]): Finding[] {
  const findings: Finding[] = [];
  const resolvedRoot = path.resolve(rootPath);

  const skills: Array<{ relFile: string; parsed: ParsedSkill }> = [];
  for (const filePath of findSkillFiles(resolvedRoot, skipPaths)) {
    let raw: string;
    try {
      raw = fs.readFileSync(filePath, "utf-8");
    } catch {
      continue;
    }
    skills.push({ relFile: path.relative(resolvedRoot, filePath), parsed: parseSkillFile(raw) });
  }

  const allSkillNames = new Set(
    skills.map((s) => s.parsed.name).filter((n) => n.length > 0),
  );

  for (const { relFile, parsed } of skills) {
    const segments: Array<{ label: "description" | "body"; text: string; baseLine: number }> = [];
    if (parsed.description) {
      segments.push({ label: "description", text: parsed.description, baseLine: parsed.descriptionLine });
    }
    if (parsed.body.trim().length > 0) {
      segments.push({ label: "body", text: parsed.body, baseLine: parsed.bodyStartLine });
    }

    for (const segment of segments) {
      // SKL001 — invisible/bidi Unicode
      const invisible = findInvisibleUnicode(segment.text);
      if (invisible) {
        findings.push({
          rule_id: "SKL001",
          title: "Invisible Unicode in agent skill file",
          severity: "critical",
          file: relFile,
          line: lineForIndex(segment.text, invisible.index, segment.baseLine),
          summary: `Skill "${parsed.name || relFile}" ${segment.label} contains ${invisible.codePoint} (${invisible.label}) at index ${invisible.index}.`,
          description:
            "Invisible or bidirectional Unicode in a skill file hides content from human reviewers while the model still reads it — the canonical tool-poisoning delivery mechanism, applied to Agent Skills instead of MCP tool metadata.",
          recommendation:
            "Remove the invisible characters and audit how they were introduced; treat the skill as compromised until reviewed.",
          confidence: evidenceConfidence("proven"),
          evidence: "proven",
        });
      }

      // SKL002 — agent-directed injection phrasing
      const phrases = matchInjectionPhrases(segment.text);
      if (phrases.strong.length > 0) {
        findings.push({
          rule_id: "SKL002",
          title: "Injection phrasing in agent skill file",
          severity: segment.label === "description" ? "high" : "medium",
          file: relFile,
          line: anchorLineForLabels(segment.text, segment.baseLine, [phrases.strong[0]]),
          summary: `Skill "${parsed.name || relFile}" ${segment.label} contains ${phrases.strong[0]}.`,
          description:
            "The skill contains instructions aimed at the agent rather than documentation for the user — the same pattern used by real-world MCP tool-poisoning attacks, now seen in Agent Skill files. Skill content enters the model's context as trusted instructions whenever the skill loads.",
          recommendation:
            "Rewrite the skill as plain documentation. If this content was not written by your team, treat the skill as compromised.",
          confidence: evidenceConfidence("likely"),
          evidence: "likely",
        });
      } else if (phrases.weak.length >= 2) {
        findings.push({
          rule_id: "SKL002",
          title: "Injection phrasing in agent skill file",
          severity: "medium",
          file: relFile,
          line: anchorLineForLabels(segment.text, segment.baseLine, phrases.weak),
          summary: `Skill "${parsed.name || relFile}" ${segment.label} combines ${phrases.weak.length} agent-directive phrases (${phrases.weak.join("; ")}).`,
          description:
            "Multiple agent-directed phrases in one skill suggest it is steering the model's behavior rather than documenting a task.",
          recommendation:
            "Review whether these directives belong in the skill; move behavioral policy into your own system prompt or agent configuration.",
          confidence: evidenceConfidence("heuristic"),
          evidence: "heuristic",
        });
      }

      // SKL003 — cross-skill shadowing
      const crossSkill = findCrossToolReference(segment.text, parsed.name, allSkillNames);
      if (crossSkill) {
        findings.push({
          rule_id: "SKL003",
          title: "Agent skill file steers another skill",
          severity: "medium",
          file: relFile,
          line: lineOfSubstring(segment.text, crossSkill.directive, segment.baseLine),
          summary: `Skill "${parsed.name || relFile}" ${segment.label} directs behavior around skill "${crossSkill.referencedTool}" ("${crossSkill.directive.trim()}…").`,
          description:
            "A skill that dictates when or how a different skill is used is the skill-shadowing attack: a malicious skill manipulates the agent's use of a legitimate skill it does not own.",
          recommendation:
            "Keep each skill scoped to documenting only its own task. Cross-skill orchestration belongs in your own agent configuration, not in skill content.",
          confidence: evidenceConfidence("likely"),
          evidence: "likely",
        });
      }
    }
  }

  return findings;
}
