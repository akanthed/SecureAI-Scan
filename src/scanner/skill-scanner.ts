import path from "node:path";
import type { Evidence, Finding, TraceStep } from "./types.js";
import { evidenceConfidence } from "./confidence.js";
import {
  findCrossToolReference,
  findInvisibleUnicode,
  matchInjectionPhrases,
} from "./tool-poisoning-checks.js";
import { matchAcrossVariants, textVariants } from "./deobfuscate.js";
import {
  detectCapabilities,
  detectUnpackDirectives,
  findSkillBundles,
  isOpaqueBlob,
  type CapabilityHit,
  type SkillBundle,
} from "./skill-bundle.js";

/**
 * Scans Agent Skill bundles (SKILL.md — Claude Skills and equivalents) for the
 * tool-poisoning shapes already detected in MCP tool metadata (MCP007–MCP009),
 * plus the bundle-level attacks that defeated every scanner surveyed in
 * "Cloak and Detonate" (arXiv:2607.02357).
 *
 * A skill's frontmatter description is always loaded into the agent's context,
 * and its body loads in full whenever the skill fires, so both are trusted
 * content an attacker can weaponize exactly like an MCP tool description. The
 * rest of the bundle is reachable the moment the skill runs.
 *
 * Rules:
 *   SKL001 — invisible/bidi Unicode in a skill's frontmatter, body or bundle
 *   SKL002 — agent-directed injection phrasing (matched through obfuscation)
 *   SKL003 — a skill's content steers when/how a different skill is used
 *   SKL004 — staged / self-extracting payload hidden in the bundle
 *   SKL005 — credential-exfiltration capability in a bundle companion file
 *   SKL006 — dynamic-context-injection command runs at load time, before any
 *            agent decision or tool-permission gate (Claude Code `` !`cmd` ``
 *            / fenced ```! blocks)
 *   SKL007 — unscoped `Bash` grant in a skill's `allowed-tools` frontmatter
 */

export interface ParsedSkill {
  name: string;
  description?: string;
  /** 1-based line of the `description:` frontmatter field, if present. */
  descriptionLine: number;
  /** Raw `allowed-tools:` frontmatter value, if present (single-line form only). */
  allowedTools?: string;
  /** 1-based line of the `allowed-tools:` frontmatter field, if present. */
  allowedToolsLine: number;
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
    return { name: "", description: undefined, descriptionLine: 1, allowedToolsLine: 1, body: raw, bodyStartLine: 1 };
  }

  let end = -1;
  for (let i = 1; i < lines.length; i++) {
    if (lines[i].trim() === "---") {
      end = i;
      break;
    }
  }
  if (end === -1) {
    return { name: "", description: undefined, descriptionLine: 1, allowedToolsLine: 1, body: raw, bodyStartLine: 1 };
  }

  let name = "";
  let description: string | undefined;
  let descriptionLine = 1;
  let allowedTools: string | undefined;
  let allowedToolsLine = 1;

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
    // Single-line form only (`allowed-tools: Bash(...) Read`); the YAML-list
    // form is out of scope for this hand-rolled parser, same as every other
    // field here.
    if (key === "allowed-tools" && value.length > 0) {
      allowedTools = value;
      allowedToolsLine = i + 1;
    }
  }

  const bodyStartLine = end + 2;
  const body = lines.slice(end + 1).join("\n");
  return { name, description, descriptionLine, allowedTools, allowedToolsLine, body, bodyStartLine };
}

/** Back-compat helper: paths of every SKILL.md under `rootPath`. */
export function findSkillFiles(rootPath: string, skipPaths?: string[]): string[] {
  return findSkillBundles(rootPath, skipPaths).map((b) => path.resolve(b.dir, "SKILL.md"));
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
 *
 * Each line is checked across its deobfuscated variants too — otherwise a
 * phrase that only matched because of cloaking (the whole point of
 * `matchAcrossVariants` upstream) would never be found again here, and the
 * finding would silently anchor to the segment's first line instead of the
 * one actually carrying the payload (visible as a blank/wrong code snippet
 * in the report).
 */
function anchorLineForLabels(text: string, baseLine: number, labels: string[]): number {
  if (labels.length === 0) return baseLine;
  const lines = text.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    for (const variant of textVariants(lines[i])) {
      const lineMatches = matchInjectionPhrases(variant.text);
      const combined = [...lineMatches.strong, ...lineMatches.weak];
      if (combined.some((label) => labels.includes(label))) return baseLine + i;
    }
  }
  return baseLine;
}

/** " (exposed after: zero-width/bidi characters removed)" — or "" when the match was in the clear. */
function transformSuffix(transforms: string[]): string {
  if (transforms.length === 0) return "";
  return ` The pattern was only visible after deobfuscation (${transforms.join("; ")}), which is itself evidence of deliberate scanner evasion.`;
}

/**
 * Evidence for a content match. A hit that required deobfuscation is promoted
 * to `proven`: ordinary prose does not contain zero-width joiners inside
 * "ignore previous instructions", nor a Cyrillic "с" inside "curl", so the
 * concealment is affirmative evidence rather than a heuristic hop.
 */
function evidenceFor(base: Evidence, transforms: string[]): Evidence {
  return transforms.length > 0 ? "proven" : base;
}

function finding(
  ruleId: string,
  title: string,
  severity: Finding["severity"],
  file: string,
  line: number,
  summary: string,
  description: string,
  recommendation: string,
  evidence: Evidence,
  trace?: TraceStep[],
): Finding {
  return {
    rule_id: ruleId,
    title,
    severity,
    file,
    line,
    summary,
    description,
    recommendation,
    confidence: evidenceConfidence(evidence),
    evidence,
    ...(trace ? { trace } : {}),
  };
}

/** SKL001–SKL003 over the SKILL.md frontmatter description and body. */
function scanSkillContent(
  bundle: SkillBundle,
  parsed: ParsedSkill,
  allSkillNames: Set<string>,
): Finding[] {
  const findings: Finding[] = [];
  const relFile = bundle.skillRelPath;
  const label = parsed.name || relFile;

  const segments: Array<{ label: "description" | "body"; text: string; baseLine: number }> = [];
  if (parsed.description) {
    segments.push({ label: "description", text: parsed.description, baseLine: parsed.descriptionLine });
  }
  if (parsed.body.trim().length > 0) {
    segments.push({ label: "body", text: parsed.body, baseLine: parsed.bodyStartLine });
  }

  for (const segment of segments) {
    // SKL001 — invisible/bidi Unicode (matched on raw text by definition).
    const invisible = findInvisibleUnicode(segment.text);
    if (invisible) {
      findings.push(
        finding(
          "SKL001",
          "Invisible Unicode in agent skill file",
          "critical",
          relFile,
          lineForIndex(segment.text, invisible.index, segment.baseLine),
          `Skill "${label}" ${segment.label} contains ${invisible.codePoint} (${invisible.label}) at index ${invisible.index}.`,
          "Invisible or bidirectional Unicode in a skill file hides content from human reviewers while the model still reads it — the canonical tool-poisoning delivery mechanism, applied to Agent Skills instead of MCP tool metadata.",
          "Remove the invisible characters and audit how they were introduced; treat the skill as compromised until reviewed.",
          "proven",
        ),
      );
    }

    // SKL002 — agent-directed injection phrasing, matched through obfuscation.
    const strongHit = matchAcrossVariants(
      segment.text,
      matchInjectionPhrases,
      (r) => r.strong,
    );
    if (strongHit) {
      const { result, transforms } = strongHit;
      findings.push(
        finding(
          "SKL002",
          "Injection phrasing in agent skill file",
          segment.label === "description" || transforms.length > 0 ? "high" : "medium",
          relFile,
          anchorLineForLabels(segment.text, segment.baseLine, [result.strong[0]]),
          `Skill "${label}" ${segment.label} contains ${result.strong[0]}.`,
          "The skill contains instructions aimed at the agent rather than documentation for the user — the same pattern used by real-world MCP tool-poisoning attacks, now seen in Agent Skill files. Skill content enters the model's context as trusted instructions whenever the skill loads." +
            transformSuffix(transforms),
          "Rewrite the skill as plain documentation. If this content was not written by your team, treat the skill as compromised.",
          evidenceFor("likely", transforms),
        ),
      );
    } else {
      const weakHit = matchAcrossVariants(
        segment.text,
        matchInjectionPhrases,
        (r) => (r.weak.length >= 2 ? r.weak : []),
      );
      if (weakHit) {
        const { result, transforms } = weakHit;
        findings.push(
          finding(
            "SKL002",
            "Injection phrasing in agent skill file",
            "medium",
            relFile,
            anchorLineForLabels(segment.text, segment.baseLine, result.weak),
            `Skill "${label}" ${segment.label} combines ${result.weak.length} agent-directive phrases (${result.weak.join("; ")}).`,
            "Multiple agent-directed phrases in one skill suggest it is steering the model's behavior rather than documenting a task." +
              transformSuffix(transforms),
            "Review whether these directives belong in the skill; move behavioral policy into your own system prompt or agent configuration.",
            evidenceFor("heuristic", transforms),
          ),
        );
      }
    }

    // SKL003 — cross-skill shadowing.
    const crossHit = matchAcrossVariants(
      segment.text,
      (candidate) => findCrossToolReference(candidate, parsed.name, allSkillNames),
      (r) => (r ? [r] : []),
    );
    if (crossHit?.result) {
      const cross = crossHit.result;
      findings.push(
        finding(
          "SKL003",
          "Agent skill file steers another skill",
          "medium",
          relFile,
          lineOfSubstring(segment.text, cross.directive, segment.baseLine),
          `Skill "${label}" ${segment.label} directs behavior around skill "${cross.referencedTool}" ("${cross.directive.trim()}…").`,
          "A skill that dictates when or how a different skill is used is the skill-shadowing attack: a malicious skill manipulates the agent's use of a legitimate skill it does not own." +
            transformSuffix(crossHit.transforms),
          "Keep each skill scoped to documenting only its own task. Cross-skill orchestration belongs in your own agent configuration, not in skill content.",
          evidenceFor("likely", crossHit.transforms),
        ),
      );
    }
  }

  return findings;
}

/**
 * SKL004 — staged / self-extracting payload.
 *
 * The SFS packing attack replaces the bundle with a benign cover SKILL.md that
 * instructs the agent to decode an opaque blob parked somewhere a scanner does
 * not look, most often `.git/`. Neither half is damning alone (skills unzip
 * fixtures; repos contain binaries), so this requires the conjunction — which
 * is what keeps it at `proven` without a keyword-only match.
 */
function scanStagedPayload(bundle: SkillBundle, parsed: ParsedSkill): Finding[] {
  const findings: Finding[] = [];
  const relFile = bundle.skillRelPath;
  const label = parsed.name || relFile;

  const opaque = bundle.files.filter(isOpaqueBlob);
  const foreignGitFiles = bundle.files.filter((f) => f.foreignInGitDir);

  // A file that is not a git internal, sitting inside a skill bundle's .git/
  // directory. Nothing in ordinary development writes there.
  for (const file of foreignGitFiles.slice(0, 5)) {
    findings.push(
      finding(
        "SKL004",
        "Staged payload hidden in agent skill bundle",
        "critical",
        file.relPath,
        1,
        `Skill "${label}" ships "${file.bundlePath}" — a non-git file inside the bundle's .git/ directory.`,
        "Files placed directly under .git/ are not created by git and are not shown by ordinary review, packaging or diff tooling, but remain readable by the agent at runtime. This is the documented hiding place for self-extracting skill payloads (arXiv:2607.02357), where a benign cover SKILL.md decodes the staged blob on first run.",
        "Remove the file and treat the skill as compromised. Nothing a skill legitimately needs belongs under .git/.",
        "proven",
      ),
    );
  }

  if (opaque.length === 0) return findings;

  // The cover instructions can live in SKILL.md or in any companion script.
  const carriers: Array<{ file: string; text: string }> = [
    { file: relFile, text: bundle.skillRaw },
    ...bundle.files
      .filter((f) => !f.binary && !isOpaqueBlob(f))
      .map((f) => ({ file: f.relPath, text: f.content })),
  ];

  for (const carrier of carriers) {
    const directives = detectUnpackDirectives(carrier.text);
    if (directives.length === 0) continue;

    // The directive must actually reference the blob. Without this link, any
    // repository whose README mentions `tar -x` and which ships a binary
    // asset would fire — the co-occurrence has to be a real one, not two
    // unrelated facts about a large directory.
    const blob = opaque.find((candidate) => {
      const base = candidate.bundlePath.split("/").pop() ?? candidate.bundlePath;
      return carrier.text.includes(candidate.bundlePath) || (base.length >= 5 && carrier.text.includes(base));
    });
    if (!blob) continue;

    // Already reported above as a .git/ staging finding — don't double-report.
    if (blob.foreignInGitDir) break;

    const directive = directives[0];
    findings.push(
      finding(
        "SKL004",
        "Staged payload hidden in agent skill bundle",
        "critical",
        carrier.file,
        directive.line,
        `Skill "${label}" instructs the agent to ${directive.label} ("${directive.match.trim()}") and ships an opaque blob at "${blob.bundlePath}" (${blob.sizeBytes} bytes).`,
        "A skill that carries unreadable data plus instructions to decode and run it is a self-extracting skill: static review sees only the benign cover, while the real payload is reconstructed at runtime. This combination defeated every scanner surveyed in arXiv:2607.02357." +
          transformSuffix(directive.transforms),
        "Ship skill logic as readable source. If the blob is genuinely needed, document its provenance and verify it out-of-band before trusting the skill.",
        "proven",
        [
          { kind: "source", file: blob.relPath, line: 1, note: `opaque payload (${blob.sizeBytes} bytes, unreadable to review)` },
          { kind: "flow", file: carrier.file, line: directive.line, note: `agent instructed to ${directive.label}` },
          { kind: "sink", file: carrier.file, line: directive.line, note: "payload reconstructed and executed in the agent's context" },
        ],
      ),
    );
    break;
  }

  return findings;
}

/**
 * Maximum line distance between a credential read and an egress call for
 * SKL005 to treat them as one flow. Widened from an initial 15 after a real
 * malicious fixture (Cisco skill-scanner's `environment-secrets` eval case)
 * split harvesting and exfiltration into separate function bodies 17 lines
 * apart — still well short of the ~35-line separation in the legitimate
 * `deploy-helper` safe fixture, which reads `~/.npmrc` and calls a registry
 * for unrelated reasons.
 */
const EXFIL_PROXIMITY_LINES = 25;

const CAPABILITY_LABEL: Record<CapabilityHit["kind"], string> = {
  "credential-access": "reads a credential file",
  "network-egress": "sends data to a hardcoded external host",
  "remote-code-exec": "downloads and executes remote code",
};

/** Does the skill's own documentation disclose that it touches credentials or the network? */
function declaresCapability(parsed: ParsedSkill, kind: CapabilityHit["kind"]): boolean {
  const declared = `${parsed.description ?? ""}\n${parsed.body}`.toLowerCase();
  if (kind === "credential-access") {
    return /\b(credential|api key|secret|token|keychain|ssh key|aws profile|authenticat)/.test(declared);
  }
  if (kind === "network-egress") {
    return /\b(upload|send|post|sync|publish|report|telemetry|webhook|api endpoint|remote server)/.test(declared);
  }
  return /\b(install|download|bootstrap|fetch.{0,20}script|remote script)/.test(declared);
}

/**
 * SKL005 — exfiltration capability in a bundle companion file.
 *
 * Fires on the *conjunction*, within a single file, of reading a concrete
 * credential path and egressing to a hardcoded external host — or on
 * remote-code-execution alone, which is self-contained by nature.
 *
 * The same-file requirement matters: a skill bundle can be a whole repository
 * when SKILL.md sits at its root, and "somewhere in this repo reads a
 * credential, somewhere else calls an external URL" describes most real
 * codebases. Requiring both halves in one file keeps the pair meaningful
 * while still catching every published attack, whose payloads are
 * self-contained scripts.
 *
 * Note this deliberately does NOT demote for test/example paths: a payload in
 * `*.test.ts` is the published Gecko Security vector precisely because every
 * other scanner skips it, and test runners auto-execute those files.
 */
function scanBundleCapabilities(bundle: SkillBundle, parsed: ParsedSkill): Finding[] {
  const label = parsed.name || bundle.skillRelPath;

  const candidates: Array<{ file: string; bundlePath: string; hits: CapabilityHit[] }> = [];
  for (const file of bundle.files) {
    if (file.binary) continue;
    const hits = detectCapabilities(file.content);
    if (hits.length > 0) candidates.push({ file: file.relPath, bundlePath: file.bundlePath, hits });
  }
  const skillHits = detectCapabilities(bundle.skillRaw);
  if (skillHits.length > 0) {
    candidates.push({ file: bundle.skillRelPath, bundlePath: "SKILL.md", hits: skillHits });
  }

  const findings: Finding[] = [];

  for (const candidate of candidates) {
    const kinds = new Set(candidate.hits.map((h) => h.kind));
    const remoteExec = kinds.has("remote-code-exec");

    // Beyond living in the same file, the credential read and the egress must
    // be near each other. A publish helper that loads ~/.npmrc in one function
    // and calls a registry forty lines later is doing two ordinary things; an
    // exfiltration payload reads the credential and ships it in adjacent
    // lines. Proximity is what separates them without full taint analysis.
    const creds = candidate.hits.filter((h) => h.kind === "credential-access");
    const egress = candidate.hits.filter((h) => h.kind === "network-egress");
    const exfilPair = creds.some((c) => egress.some((e) => Math.abs(c.line - e.line) <= EXFIL_PROXIMITY_LINES));

    if (!exfilPair && !remoteExec) continue;

    const trace: TraceStep[] = candidate.hits.map((hit) => ({
      kind: hit.kind === "credential-access" ? ("source" as const) : ("sink" as const),
      file: candidate.file,
      line: hit.line,
      note: `${CAPABILITY_LABEL[hit.kind]}: ${hit.match}`,
    }));

    const primaryHit =
      candidate.hits.find((h) => h.kind === "credential-access") ?? candidate.hits[0];
    const transforms = candidate.hits.find((h) => h.transforms.length > 0)?.transforms ?? [];

    const undeclared = exfilPair
      ? !declaresCapability(parsed, "credential-access") || !declaresCapability(parsed, "network-egress")
      : !declaresCapability(parsed, "remote-code-exec");

    const kindList = [...kinds]
      .filter((k) => (exfilPair ? k !== "remote-code-exec" : k === "remote-code-exec"))
      .map((k) => CAPABILITY_LABEL[k])
      .join(" and ");
    const companionNote =
      candidate.bundlePath === "SKILL.md"
        ? ""
        : ` The capability lives in "${candidate.bundlePath}", not in SKILL.md.`;

    findings.push(
      finding(
        "SKL005",
        exfilPair
          ? "Credential exfiltration capability in agent skill bundle"
          : "Remote code execution in agent skill bundle",
        "critical",
        candidate.file,
        primaryHit.line,
        `Skill "${label}" ${kindList} (${primaryHit.match.trim()}).`,
        (exfilPair
          ? "The bundle both reads a specific credential file and transmits to a hardcoded external host, in the same file. Together these form a complete exfiltration path that runs with the agent's full local permissions the moment the skill fires."
          : "The bundle downloads code from a hardcoded external host and executes it, handing the remote operator arbitrary execution in the agent's context.") +
          companionNote +
          (undeclared
            ? " The skill's own description does not disclose this behaviour."
            : " The skill documents related behaviour — confirm the destination and scope are what you expect.") +
          transformSuffix(transforms),
        "Remove the capability or move it behind an explicit, user-approved configuration value. Rotate any credential the bundle could have reached, and audit where the skill came from.",
        undeclared ? "proven" : "likely",
        trace.length >= 2 ? trace.slice(0, 8) : undefined,
      ),
    );
  }

  return findings;
}

/** SKL001 over every text file in the bundle, not just SKILL.md. */
function scanBundleInvisibleUnicode(bundle: SkillBundle, parsed: ParsedSkill): Finding[] {
  const findings: Finding[] = [];
  const label = parsed.name || bundle.skillRelPath;
  for (const file of bundle.files) {
    if (file.binary) continue;
    // Markdown docs legitimately contain no invisible controls either; the
    // only common false source is minified/generated assets, excluded above.
    const invisible = findInvisibleUnicode(file.content);
    if (!invisible) continue;
    findings.push(
      finding(
        "SKL001",
        "Invisible Unicode in agent skill file",
        "critical",
        file.relPath,
        lineForIndex(file.content, invisible.index, 1),
        `Skill "${label}" companion file "${file.bundlePath}" contains ${invisible.codePoint} (${invisible.label}).`,
        "Invisible or bidirectional Unicode hides content from human reviewers while the model still reads it. Companion files in a skill bundle load into the agent's context exactly like SKILL.md does.",
        "Remove the invisible characters and audit how they were introduced; treat the skill as compromised until reviewed.",
        "proven",
      ),
    );
  }
  return findings;
}

/**
 * SKL006 — Claude Code's dynamic-context-injection syntax (`` !`cmd` `` inline
 * and fenced ```! blocks) runs shell commands the instant a skill's content
 * is rendered, before Claude ever sees the text and before any tool
 * permission gate applies. It is preprocessing, not a Bash tool call, so it
 * never appears as a tool invocation in the transcript. A skill that uses
 * this mechanism to fetch-and-execute remote code, or that splices its own
 * invocation arguments (`$ARGUMENTS`, `$0`..`$9`) directly into the command
 * text, gets code execution or shell injection with zero agent decision and
 * zero confirmation prompt — a materially worse position than SKL005, which
 * still requires the agent to choose to run something.
 */
const INLINE_EXEC_RE = /(^|[ \t])!`([^`\r\n]+)`/gm;
const FENCED_EXEC_RE = /```!\r?\n([\s\S]*?)```/g;

// $ARGUMENTS / $ARGUMENTS[N] / the $0..$9 shorthand — the built-in
// placeholders substituted as raw text before the shell ever parses the
// command. Named placeholders from a skill's own `arguments:` list are not
// matched here: without knowing the declared names, matching bare `$word`
// would collide with ordinary shell variables (`$HOME`, `$PATH`) that have
// nothing to do with skill arguments.
const ARGUMENT_SPLICE_RE = /\$ARGUMENTS(?:\[\d+\])?|\$[0-9](?!\w)/;

function extractDynamicExecBlocks(raw: string): Array<{ text: string; index: number }> {
  const blocks: Array<{ text: string; index: number }> = [];
  let m: RegExpExecArray | null;
  INLINE_EXEC_RE.lastIndex = 0;
  while ((m = INLINE_EXEC_RE.exec(raw))) {
    blocks.push({ text: m[2], index: m.index + m[1].length + 2 });
  }
  FENCED_EXEC_RE.lastIndex = 0;
  while ((m = FENCED_EXEC_RE.exec(raw))) {
    blocks.push({ text: m[1], index: m.index + 4 });
  }
  return blocks;
}

function scanDynamicContextExecution(bundle: SkillBundle, parsed: ParsedSkill): Finding[] {
  const findings: Finding[] = [];
  const label = parsed.name || bundle.skillRelPath;
  const relFile = bundle.skillRelPath;

  for (const block of extractDynamicExecBlocks(bundle.skillRaw)) {
    const line = lineForIndex(bundle.skillRaw, block.index, 1);
    const hits = detectCapabilities(block.text);
    const remoteExec = hits.find((h) => h.kind === "remote-code-exec");
    const creds = hits.filter((h) => h.kind === "credential-access");
    const egress = hits.filter((h) => h.kind === "network-egress");
    const exfilPair = creds.length > 0 && egress.length > 0;

    if (remoteExec || exfilPair) {
      const primaryMatch = (remoteExec ?? creds[0]).match;
      findings.push(
        finding(
          "SKL006",
          "Load-time command execution in agent skill",
          "critical",
          relFile,
          line,
          `Skill "${label}" runs "${block.text.trim().slice(0, 100)}" via dynamic context injection — this executes the moment the skill is read, before Claude sees the content or any tool permission applies.`,
          remoteExec
            ? "Claude Code's `` !`cmd` `` / ```! syntax preprocesses and runs shell commands before the skill's content ever reaches the model, and the run never appears as a Bash tool call in the transcript. This command downloads and executes remote code, so merely loading the skill is enough to compromise the machine — no agent decision or user confirmation is involved."
            : "This block both reads a credential and reaches a hardcoded external host, and it runs automatically the moment the skill loads via dynamic context injection — before any tool-permission gate applies.",
          "Remove dynamic-context-injection commands that fetch or transmit data over the network. Keep this mechanism to local, static commands (e.g. `git diff HEAD`).",
          "proven",
          [
            { kind: "source", file: relFile, line, note: "dynamic context injection block (`!` syntax)" },
            { kind: "sink", file: relFile, line, note: `${primaryMatch} — executes at load time` },
          ],
        ),
      );
      continue;
    }

    if (ARGUMENT_SPLICE_RE.test(block.text)) {
      findings.push(
        finding(
          "SKL006",
          "Skill argument spliced into load-time command",
          "high",
          relFile,
          line,
          `Skill "${label}" interpolates its own invocation arguments directly into a dynamic-context-injection command ("${block.text.trim().slice(0, 100)}").`,
          "Claude Code substitutes `$ARGUMENTS`/`$0`..`$9` as raw text into the command before any shell parsing happens, and the command then runs immediately as preprocessing. Whatever the caller supplies as an argument — a user, or Claude acting on untrusted context it read — becomes part of the shell command line verbatim: classic argument/command injection, except it fires at skill-load time instead of through a reviewable tool call.",
          "Quote and validate arguments before using them in a dynamic-context command, or avoid interpolating raw arguments into `` !`cmd` `` blocks entirely.",
          "likely",
        ),
      );
    }
  }

  return findings;
}

/**
 * SKL007 — an unrestricted `Bash` entry in a skill's `allowed-tools`
 * frontmatter pre-approves arbitrary shell execution for the whole turn that
 * invokes the skill, without a confirmation prompt. Anthropic's own docs
 * warn "a skill can grant itself broad tool access" for exactly this field.
 * Every legitimate example scopes the grant to a specific command prefix
 * (`Bash(git add *)`, `Bash(gh *)`); a bare `Bash` or `Bash(*)` has no
 * ordinary reading — it is a blanket shell-execution grant, which is why
 * this is a parsed config fact (`proven`), not a heuristic.
 */
const TOOL_TOKEN_RE = /([A-Za-z][A-Za-z0-9_]*)(\([^)]*\))?/g;

function scanAllowedToolsOverreach(bundle: SkillBundle, parsed: ParsedSkill): Finding[] {
  if (!parsed.allowedTools) return [];
  const label = parsed.name || bundle.skillRelPath;
  const findings: Finding[] = [];

  TOOL_TOKEN_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = TOOL_TOKEN_RE.exec(parsed.allowedTools))) {
    const [, toolName, scope] = m;
    if (toolName !== "Bash") continue;
    const unscoped = !scope || /^\(\s*\*\s*\)$/.test(scope);
    if (!unscoped) continue;

    findings.push(
      finding(
        "SKL007",
        "Unscoped Bash grant in agent skill frontmatter",
        "high",
        bundle.skillRelPath,
        parsed.allowedToolsLine,
        `Skill "${label}" declares "allowed-tools: ${parsed.allowedTools}" — an unrestricted Bash grant.`,
        "The `allowed-tools` frontmatter pre-approves the listed tools for the whole turn that invokes the skill, with no confirmation prompt. A bare `Bash` (or `Bash(*)`) grants arbitrary shell execution rather than a specific command, and Claude may auto-invoke the skill itself unless it is marked `disable-model-invocation`.",
        "Scope the grant to the exact command(s) the skill needs, e.g. `Bash(git status *)`, rather than a bare `Bash`.",
        "proven",
      ),
    );
    break; // one finding is enough signal for review; further Bash tokens are the same fact.
  }

  return findings;
}

export function scanSkillFiles(rootPath: string, skipPaths?: string[]): Finding[] {
  const findings: Finding[] = [];
  const bundles = findSkillBundles(rootPath, skipPaths);

  const parsedByBundle = new Map<SkillBundle, ParsedSkill>();
  for (const bundle of bundles) {
    parsedByBundle.set(bundle, parseSkillFile(bundle.skillRaw));
  }

  const allSkillNames = new Set(
    [...parsedByBundle.values()].map((p) => p.name).filter((n) => n.length > 0),
  );

  for (const bundle of bundles) {
    const parsed = parsedByBundle.get(bundle)!;
    findings.push(...scanSkillContent(bundle, parsed, allSkillNames));
    findings.push(...scanBundleInvisibleUnicode(bundle, parsed));
    findings.push(...scanStagedPayload(bundle, parsed));
    findings.push(...scanBundleCapabilities(bundle, parsed));
    findings.push(...scanDynamicContextExecution(bundle, parsed));
    findings.push(...scanAllowedToolsOverreach(bundle, parsed));
  }

  return findings;
}
