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
    re: /\b(?:read|cat|open|access|fetch|load)\b[^.]{0,60}(?:~\/\.ssh|id_rsa|id_ed25519|\.env\b|\.aws\/credentials|\.netrc|private[_ ]key|api[_ ]?keys?\b)/i,
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
];

const WEAK_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /\bbefore\s+(?:using|calling|invoking)\s+this\s+tool\b/i, label: "\"before using this tool\" precondition" },
  { re: /\binstead\s+of\s+(?:calling|using|invoking)\b/i, label: "tool substitution directive" },
  { re: /\bdo\s+not\s+mention\b/i, label: "\"do not mention\" directive" },
  { re: /\balways\s+include\b[^.]{0,40}\bin\s+(?:your|the)\s+(?:response|output|prompt)/i, label: "forced response content" },
  { re: /\bthis\s+is\s+a\s+(?:system|developer)\s+(?:message|instruction)\b/i, label: "role-claim in description" },
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

const DIRECTIVE_RE = /\b(when|whenever|before|after|instead\s+of|prior\s+to)\b[^.]{0,50}\b(call(?:s|ed|ing)?|use[sd]?|using|invok(?:e[sd]?|ing)|run(?:s|ning)?)\b/i;

/**
 * A description referencing *another* registered tool by name combined with a
 * behavioral directive ("when X is called, first…") — the tool-shadowing
 * attack. Tool names shorter than 4 chars are skipped: they collide with
 * ordinary words far too often.
 */
export function findCrossToolReference(
  text: string,
  ownName: string,
  allToolNames: Iterable<string>,
): CrossToolHit | undefined {
  const directive = DIRECTIVE_RE.exec(text);
  if (!directive) return undefined;
  for (const other of allToolNames) {
    if (other === ownName || other.length < 4) continue;
    const escaped = other.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (new RegExp(`\\b${escaped}\\b`, "i").test(text)) {
      return { referencedTool: other, directive: directive[0] };
    }
  }
  return undefined;
}
