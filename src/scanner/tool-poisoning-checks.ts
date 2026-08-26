/**
 * Content checks for MCP tool-poisoning (MCP007–MCP009), shared by the TS AST
 * rule, the Python scanner, and the MCP config scanner so all three languages
 * flag identical patterns.
 *
 * Precision contract: these checks target instructions aimed at the *agent*
 * (override behavior, hide from the user, exfiltrate files/data, shadow other
 * tools). Ordinary usage guidance in a description ("Use this tool to fetch
 * weather. Do not pass PII.") must never fire.
 */

import { identifierTokens } from "./confidence.js";

export interface InvisibleCharHit {
  /** Unicode code point, formatted U+XXXX. */
  codePoint: string;
  /** Human label for the character class. */
  label: string;
  /** 0-based character index within the string. */
  index: number;
}

const INVISIBLE_RANGES: Array<{ start: number; end: number; label: string }> = [
  { start: 0x200b, end: 0x200d, label: "zero-width character" },
  { start: 0x2060, end: 0x2060, label: "word joiner" },
  { start: 0xfeff, end: 0xfeff, label: "zero-width no-break space" },
  { start: 0x202a, end: 0x202e, label: "bidirectional control" },
  { start: 0x2066, end: 0x2069, label: "bidirectional isolate" },
  { start: 0xe0000, end: 0xe007f, label: "Unicode tags block (invisible to humans, visible to the model)" },
];

/** First invisible/bidi character in the text, or undefined if clean. */
export function findInvisibleUnicode(text: string): InvisibleCharHit | undefined {
  let index = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0)!;
    for (const range of INVISIBLE_RANGES) {
      if (cp >= range.start && cp <= range.end) {
        return {
          codePoint: `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`,
          label: range.label,
          index,
        };
      }
    }
    index += ch.length;
  }
  return undefined;
}

export interface InjectionPhraseResult {
  /** Any single strong match justifies a finding on its own. */
  strong: string[];
  /** Weak signals; require two or more to report (heuristic tier). */
  weak: string[];
}

/** Phrases that only make sense as instructions to the agent, not the user. */
const STRONG_PATTERNS: Array<{ re: RegExp; label: string }> = [
  {
    re: /ignore\s+(?:all\s+|any\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|messages?|context|rules?)/i,
    label: "instruction override (\"ignore previous instructions\")",
  },
  {
    re: /do\s+not\s+(?:tell|inform|notify|mention(?:\s+this)?\s+to|reveal(?:\s+this)?\s+to|show(?:\s+this)?\s+to|alert)\s+the\s+user/i,
    label: "concealment from the user",
  },
  {
    re: /<\s*(?:important|secret|system|hidden|admin)\s*>/i,
    label: "pseudo-system tag in description",
  },
  {
    // Every alternative must be a concrete credential *location* — a path or
    // a filename. A bare "API keys" is ordinary English: the AI SDK's own
    // skill documentation says "Load API keys securely using loadApiKey",
    // which is security advice, not an exfiltration directive. Requiring a
    // path/extension shape is what separates the two.
    re: /\b(?:read|cat|open|access|fetch|load)\b[^.]{0,60}(?:~\/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws\/credentials|\.netrc|private[_ ]key(?:\.[a-z0-9]+|\s+file)|api[_ ]?keys?\.(?:json|txt|ya?ml|env|ini|cfg)|(?:the\s+)?api[_ ]?keys?\s+file)/i,
    label: "instruction to read credential files",
  },
  {
    re: /\b(?:send|forward|post|upload|transmit|exfiltrate)\b[^.]{0,60}\bto\s+https?:\/\//i,
    label: "instruction to send data to an external URL",
  },
  {
    re: /\byou\s+(?:must|should)\s+(?:first\s+)?(?:always\s+)?(?:run|execute|call)\b[^.]{0,60}\bbefore\s+(?:responding|answering|any)/i,
    label: "mandatory pre-action injected into the agent loop",
  },
  {
    re: /ignore\s+(?:all\s+|any\s+)?(?:future|subsequent|upcoming|later)\s+(?:instructions?|messages?|rules?|guardrails?|safety\s+(?:instructions?|guidelines?))/i,
    label: "forward-looking instruction override (\"ignore future/subsequent instructions\")",
  },
];

const WEAK_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bbefore\s+(?:using|calling|invoking)\s+this\s+tool\b/i, label: "\"before using this tool\" precondition" },
  { re: /\binstead\s+of\s+(?:calling|using|invoking)\b/i, label: "tool substitution directive" },
  { re: /\bdo\s+not\s+mention\b/i, label: "\"do not mention\" directive" },
  { re: /\balways\s+include\b[^.]{0,40}\bin\s+(?:your|the)\s+(?:response|output|prompt)/i, label: "forced response content" },
  { re: /\bthis\s+is\s+a\s+(?:system|developer)\s+(?:message|instruction)\b/i, label: "role-claim in description" },
  {
    re: /\b(?:once|after|when)\s+(?:this\s+is\s+|you(?:'re| are)\s+)?(?:triggered|activated)\b|\b(?:the\s+)?trigger\s+(?:word|phrase)\s+(?:is\s+)?(?:seen|used|given|detected)\b|\bcondition\s+is\s+met\b/i,
    label: "delayed/conditional activation phrasing",
  },
];

export function matchInjectionPhrases(text: string): InjectionPhraseResult {
  const strong = STRONG_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
  const weak = WEAK_PATTERNS.filter((p) => p.re.test(text)).map((p) => p.label);
  return { strong, weak };
}

export interface CrossToolHit {
  /** The other tool whose behavior this description tries to steer. */
  referencedTool: string;
  /** The directive phrase that makes the reference behavioral. */
  directive: string;
}

const TRIGGER_RE = /\b(when|whenever|before|after|instead\s+of|prior\s+to)\b/gi;
const VERB_RE = /\b(call(?:s|ed|ing)?|use[sd]?|using|invok(?:e[sd]?|ing)|run(?:s|ning)?)\b/i;

/**
 * A description referencing *another* registered tool by name combined with a
 * behavioral directive ("when X is called, first…") — the tool-shadowing
 * attack. Tool names shorter than 4 chars are skipped: they collide with
 * ordinary words far too often.
 *
 * Three precision constraints, the first two added after the AI SDK's own
 * skill documentation tripped this rule three times, the third after an
 * ecosystem audit of `awslabs/mcp` found five more false positives — all
 * ordinary "use X for Y" / "after invoking X" cross-references between
 * sibling tools/skills the *same* author documented, not redirection:
 *
 *  1. The directive and the tool name must appear in the *same sentence*.
 *     Scanning a whole multi-page skill body for "a directive somewhere and a
 *     sibling skill's name somewhere" matches almost any long document that
 *     mentions its neighbours — "Reuse tools when appropriate" 200 lines away
 *     from a reference to another skill is not shadowing.
 *
 *  2. The name must not be part of a package specifier or path. `\b` does not
 *     help here because "-" and "/" are already non-word characters, so a
 *     skill named "ai-sdk" matched inside every "@ai-sdk/provider-utils" in
 *     the file.
 *
 *  3. The tool name must sit *between* the trigger word and the directive
 *     verb — the grammatical subject of the trigger clause, not the verb's
 *     object. "When `send_email` is called, route through this tool" (the
 *     real vulnerable fixture) puts the referenced tool right after "when,"
 *     ahead of "called": the trigger clause is *about* that tool, and the
 *     action commanded is self-referential ("this tool"). "When to Use
 *     Transact vs `readonly_query`" and "After presenting the structure,
 *     offer to use `sample_dataset`" put the referenced tool *after* the
 *     verb, as what the agent is told to use for its own purpose — ordinary
 *     comparison/cross-reference documentation between tools the same
 *     author owns, ubiquitous across `awslabs/mcp`'s own servers. Matching
 *     "tool name anywhere in a sentence with a trigger and a verb" cannot
 *     tell these apart; matching only the span before the verb can.
 */
function referencesToolName(segment: string, toolName: string): boolean {
  const escaped = toolName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  // Reject when preceded by @ or /, or followed by / — i.e. it is a package
  // or path component rather than a standalone reference to the tool.
  const re = new RegExp(`(^|[^\\w@/-])${escaped}(?![\\w/-])`, "i");
  return re.test(segment);
}

/** Split into sentences, also breaking on newlines and list markers. */
export function sentences(text: string): string[] {
  return text
    .split(/(?<=[.!?:])\s+|\r?\n/)
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/**
 * True when every word in `candidate` already appears in `ownName` — i.e.
 * `candidate` is describing the same thing `ownName` names, not a distinct
 * tool/skill. Catches aws-mcp's "amazon aurora dsql" skill referencing
 * "dsql": the word is that skill's own product name, appearing constantly
 * throughout its own documentation (`**When:** Always load for guidance
 * using or updating the DSQL MCP server`), and a *different* skill in the
 * same monorepo happens to be registered under the bare name "dsql" — a
 * naming collision, not this skill steering a foreign one.
 */
function isSelfDescribing(ownName: string, candidate: string): boolean {
  const ownTokens = new Set(identifierTokens(ownName));
  const candidateTokens = identifierTokens(candidate);
  return candidateTokens.length > 0 && candidateTokens.every((t) => ownTokens.has(t));
}

export function findCrossToolReference(
  text: string,
  ownName: string,
  allToolNames: Iterable<string>,
): CrossToolHit | undefined {
  const names = [...allToolNames].filter(
    (n) => n !== ownName && n.length >= 4 && !isSelfDescribing(ownName, n),
  );
  if (names.length === 0) return undefined;

  for (const segment of sentences(text)) {
    TRIGGER_RE.lastIndex = 0;
    let trigger: RegExpExecArray | null;
    while ((trigger = TRIGGER_RE.exec(segment))) {
      const afterTrigger = segment.slice(trigger.index + trigger[0].length);
      const verb = VERB_RE.exec(afterTrigger);
      if (!verb) continue;
      // The tool name must fall strictly between the trigger and the verb —
      // the subject of the trigger clause, not the verb's object. See the
      // constraint-3 comment on referencesToolName for why.
      const subjectSpan = afterTrigger.slice(0, verb.index);
      for (const other of names) {
        if (referencesToolName(subjectSpan, other)) {
          return { referencedTool: other, directive: trigger[0] + afterTrigger.slice(0, verb.index + verb[0].length) };
        }
      }
    }
  }
  return undefined;
}

export interface RemoteInstructionHit {
  /** The URL the agent is directed to fetch. */
  url: string;
  /** The full sentence carrying both the fetch and the follow directive. */
  directive: string;
}

const URL_RE = /https?:\/\/[^\s)"'<>]+/;
const FETCH_VERB_RE = /\b(?:fetch|download|retrieve|load|check|read|get|pull)\b/i;

/**
 * The fetched content must be named as the thing to act on, not merely
 * mentioned near a URL. "follow the standard PR workflow" or "follow @handle
 * for updates" must never match — the object of the verb has to resolve back
 * to the fetched content itself ("the instructions", "it", "what it says").
 */
const FOLLOW_DIRECTIVE_RE =
  /\b(?:follow|execute|run|apply|obey|do\s+(?:exactly\s+)?what)\b[^.]{0,40}\b(?:instructions?|it\s+says|it\s+exactly|this\s+exactly|those\s+steps|that\s+exactly|whatever\s+(?:it|that|they)\s+(?:says?|returns?|contains?))\b/i;

/**
 * The "Circus of Skills" attack (Air Security, June 2026): a skill's real
 * instructions are never checked into the reviewed bundle at all — they are
 * fetched from an external URL at runtime and executed as if they were the
 * skill's own content. Static review of the bundle sees only an innocuous
 * fetch-a-doc step; the payload can change on the server at any time after
 * install, with nothing in the bundle to re-review.
 *
 * Both signals — a fetch verb pointed at a URL, and a directive telling the
 * agent to treat the fetched content as instructions to execute — must land
 * in the same sentence. A skill that says "Fetch the changelog from
 * https://example.com/CHANGELOG.md for context" is ordinary documentation
 * lookup; nothing tells the agent to *act on* what comes back.
 */
export function findRemoteInstructionDirective(text: string): RemoteInstructionHit | undefined {
  for (const segment of sentences(text)) {
    const urlMatch = URL_RE.exec(segment);
    if (!urlMatch) continue;
    if (!FETCH_VERB_RE.test(segment)) continue;
    if (!FOLLOW_DIRECTIVE_RE.test(segment)) continue;
    return { url: urlMatch[0], directive: segment };
  }
  return undefined;
}

export interface PersistenceWriteHit {
  /** The identity/context file the skill instructs the agent to write into. */
  targetFile: string;
  directive: string;
}

const WRITE_VERB_RE = /\b(?:write|append|add|insert|inject|save|persist|prepend)\b/i;
const PERSISTENCE_TARGET_RE = /\b(SOUL|MEMORY|AGENTS?|CLAUDE)\.md\b/;
const PERSISTENCE_SIGNAL_RE =
  /\b(?:across\s+sessions?|future\s+sessions?|every\s+session|next\s+time\s+(?:the\s+)?(?:agent|claude|it)\s+(?:runs?|loads?|starts?)|survive[s]?\s+(?:a\s+)?restart|silently|without\s+(?:telling|informing|notifying|showing)\s+(?:the\s+)?user|do\s+not\s+(?:tell|inform|mention|reveal|show)\b[^.]{0,30}\buser\b)\b/i;

/**
 * Cross-file persistence / backdoor propagation: a skill that instructs the
 * agent to write into a *different* trust-elevated context file (`MEMORY.md`,
 * `SOUL.md`, `AGENTS.md`, `CLAUDE.md`) so its behavior survives after the
 * skill itself is removed and spreads to other sessions or collaborators who
 * load that file. This is precisely how the ClawHavoc campaign backdoored
 * `MEMORY.md`/`SOUL.md` for session persistence, and the scenario the Cloud
 * Security Alliance's May 2026 research note names "persistence and
 * propagation".
 *
 * Requires a write verb, the target file, and a persistence-or-concealment
 * signal all in the same sentence — an ordinary "keep AGENTS.md up to date
 * with new build steps" documentation-sync skill has no reason to mention
 * surviving restarts or hiding the change from the user, so it does not
 * collide with this pattern.
 */
export function findPersistenceWriteDirective(text: string): PersistenceWriteHit | undefined {
  for (const segment of sentences(text)) {
    const targetMatch = PERSISTENCE_TARGET_RE.exec(segment);
    if (!targetMatch) continue;
    if (!WRITE_VERB_RE.test(segment)) continue;
    if (!PERSISTENCE_SIGNAL_RE.test(segment)) continue;
    return { targetFile: targetMatch[0], directive: segment };
  }
  return undefined;
}

export interface UnsafeDeserializationHit {
  match: string;
  index: number;
}

/**
 * YAML/JSON deserialization tags that construct language-native objects
 * (Python `!!python/object`, Ruby `!ruby/object`, JS "function" tags) rather
 * than plain scalars/mappings. These have no legitimate use in a skill's
 * frontmatter or a bundled config file — a hand-written skill manifest never
 * needs to deserialize a class instance or a function — so any match is
 * `proven`, the same standing as SKL001's invisible-Unicode check. OWASP
 * Agentic Skills Top 10 catalogs this under AST04 (Insecure Metadata):
 * "safe parsing with approved YAML/JSON loaders".
 */
const UNSAFE_DESERIALIZATION_RE =
  /!!?(?:python|ruby|js|javascript|perl)\/(?:object|object\/(?:new|apply)|function|module|code|eval|exec)\b|tag:yaml\.org,2002:(?:python|js|ruby)\//i;

export function findUnsafeDeserializationTag(text: string): UnsafeDeserializationHit | undefined {
  const match = UNSAFE_DESERIALIZATION_RE.exec(text);
  if (!match) return undefined;
  return { match: match[0], index: match.index };
}
