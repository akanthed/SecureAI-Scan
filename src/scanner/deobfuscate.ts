/**
 * Deobfuscation / normalization layer for content-based rules.
 *
 * Motivation: "Cloak and Detonate" (Ji et al., arXiv:2607.02357, July 2026)
 * showed that nine published Agent Skill scanners could be bypassed >80% of
 * the time by *reify* transformations — rewrites that change the bytes a rule
 * matches while the agent still reassembles the original at runtime:
 *
 *   zero-width insertion   eval        -> e​val
 *   confusable glyphs      curl        -> сurl        (Cyrillic U+0441)
 *   case flip              eval        -> EvAl
 *   variable splicing      curl        -> 'cu' + 'rl'
 *   intra-word line split  eval(x)     -> ev\nal(x)
 *
 * Strategy here: never match on one fixed byte sequence. Produce a small set
 * of normalized *variants* of the text and let callers match against all of
 * them, taking the union of hits.
 *
 * The precision payoff — and the reason this does not weaken the evidence
 * contract — is inverted from the usual heuristic tradeoff: a phrase that
 * matches ONLY after deobfuscation is *stronger* evidence than one that
 * matches raw. Ordinary documentation does not contain a Cyrillic "с" inside
 * the word "curl", and prose is not written with zero-width joiners inside
 * "ignore previous instructions". A deobfuscation-only match is affirmative
 * evidence of deliberate evasion, so callers promote rather than demote it.
 *
 * Case-flip needs no transform: every pattern in tool-poisoning-checks.ts is
 * already case-insensitive.
 */

/**
 * Invisible / bidi / tag code points. Kept in sync with INVISIBLE_RANGES in
 * tool-poisoning-checks.ts, which reports them as findings in their own right
 * (SKL001/MCP007); here we strip them so the text underneath can be matched.
 */
const INVISIBLE_RE =
  /[​-‍⁠﻿‪-‮⁦-⁩]|[󠀀-󠁿]/gu;

/** Remove zero-width, bidi-control and Unicode-tag characters. */
export function stripInvisible(text: string): string {
  return text.replace(INVISIBLE_RE, "");
}

/**
 * Confusable → ASCII folding table.
 *
 * Deliberately limited to characters that are visually identical (or near
 * enough to fool a reviewer) to an ASCII letter or digit in a normal
 * proportional font: Cyrillic and Greek lookalikes, fullwidth forms, and
 * mathematical alphanumerics. It is NOT a general transliteration table —
 * folding accented Latin ("é" -> "e") would corrupt ordinary non-English
 * documentation for no security benefit, since "é" is not used to disguise
 * an ASCII command.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic → Latin
  "а": "a", "А": "A", "е": "e", "Е": "E",
  "о": "o", "О": "O", "р": "p", "Р": "P",
  "с": "c", "С": "C", "у": "y", "У": "Y",
  "х": "x", "Х": "X", "і": "i", "І": "I",
  "ј": "j", "Ј": "J", "ѕ": "s", "Ѕ": "S",
  "к": "k", "К": "K", "м": "m", "М": "M",
  "н": "h", "Н": "H", "в": "B", "В": "B",
  "т": "T", "Т": "T", "һ": "h", "ԁ": "d",
  // Greek → Latin
  "ο": "o", "Ο": "O", "α": "a", "Α": "A",
  "ν": "v", "ε": "e", "Ε": "E", "ρ": "p",
  "Ρ": "P", "τ": "t", "Τ": "T", "Β": "B",
  "Η": "H", "Κ": "K", "Μ": "M", "Ν": "N",
  "Ι": "I", "Χ": "X", "Ζ": "Z", "ι": "i",
  // Armenian / Cherokee lookalikes seen in homoglyph kits
  "օ": "o", "Ꭰ": "D", "Ꮐ": "G", "Ꮮ": "L",
  // Fullwidth forms
  "ａ": "a", "ｃ": "c", "ｅ": "e", "ｌ": "l",
  "ｒ": "r", "ｕ": "u", "ｖ": "v",
};

/** Fold visually-confusable Unicode letters to their ASCII lookalikes. */
export function foldConfusables(text: string): string {
  let out = "";
  for (const ch of text) {
    out += CONFUSABLES[ch] ?? ch;
  }
  return out;
}

/**
 * Join adjacent quoted string literals combined with `+` or `.` — the
 * "variable splicing" evasion (`'cu' + 'rl'`, `"sys" . "tem"`). Applied
 * repeatedly so chains of three or more fragments collapse fully.
 *
 * Only same-quote-style joins are folded, and only when the operator is
 * surrounded by nothing but whitespace, so ordinary concatenation of two
 * *separate* meaningful strings ("Hello, " + name) is unaffected — that has
 * an identifier on one side, not a literal.
 */
export function joinSplicedLiterals(text: string): string {
  const SPLICE = /(['"])([^'"\n]*)\1\s*[+.]\s*\1([^'"\n]*)\1/g;
  let out = text;
  for (let i = 0; i < 8; i++) {
    const next = out.replace(SPLICE, (_m, q: string, a: string, b: string) => `${q}${a}${b}${q}`);
    if (next === out) break;
    out = next;
  }
  return out;
}

/**
 * Join line breaks that fall *inside* a word — the per-line splitting evasion
 * (`ev\nal(x)`). This is intentionally lossy for prose: wrapped English text
 * ("the\nuser") also gets joined into nonsense ("theuser"). That is fine and
 * by design, because this variant is only ever matched *in addition to* the
 * others and contributes hits, never suppresses them. A phrase broken by
 * normal word wrap still matches the structure-preserving variants, whose
 * patterns use `\s+`.
 *
 * Indented continuation lines (markdown lists, code blocks) are left alone —
 * leading whitespace after the newline means the break was not mid-token.
 */
export function joinIntraWordBreaks(text: string): string {
  return text.replace(/(\w)\r?\n(\w)/g, "$1$2");
}

export interface TextVariant {
  text: string;
  /**
   * Human-readable labels of the transforms that actually changed the text.
   * Empty for the raw variant. Non-empty means a hit found here was hidden
   * behind an obfuscation layer.
   */
  transforms: string[];
}

/**
 * The raw text plus deobfuscated variants, deduplicated. Always returns at
 * least one entry (the raw text, with no transforms). Callers should match
 * every variant and take the union of results, using `transforms` to decide
 * evidence: a hit present only in a variant with a non-empty `transforms`
 * list was deliberately concealed.
 */
export function textVariants(text: string): TextVariant[] {
  const variants: TextVariant[] = [{ text, transforms: [] }];
  const seen = new Set([text]);

  const steps: Array<{ label: string; fn: (s: string) => string }> = [
    { label: "zero-width/bidi characters removed", fn: stripInvisible },
    { label: "Unicode homoglyphs folded to ASCII", fn: foldConfusables },
    { label: "spliced string literals joined", fn: joinSplicedLiterals },
  ];

  // Cumulative application: each transform layered on the previous, so a
  // payload hidden behind two techniques at once is still recovered.
  let current = text;
  const applied: string[] = [];
  for (const step of steps) {
    const next = step.fn(current);
    if (next !== current) {
      applied.push(step.label);
      current = next;
      if (!seen.has(current)) {
        seen.add(current);
        variants.push({ text: current, transforms: [...applied] });
      }
    }
  }

  // The intra-word join is kept as a separate leaf rather than part of the
  // cumulative chain: it is the lossy one, so it should never be the base
  // for further transforms.
  const joined = joinIntraWordBreaks(current);
  if (joined !== current && !seen.has(joined)) {
    seen.add(joined);
    variants.push({ text: joined, transforms: [...applied, "intra-word line breaks joined"] });
  }

  return variants;
}

/**
 * Run `matcher` over every variant of `text` and return the richest result,
 * together with the transforms that were needed to expose anything the raw
 * text did not already reveal.
 *
 * `pick` extracts the comparable hit list from the matcher's return value so
 * this works for matchers with different shapes.
 *
 * Note the comparison is against the *set* of raw hits, not merely "did the
 * raw text match at all". Otherwise an attacker could mask the evasion signal
 * by leaving one innocuous-looking phrase in the clear: the raw hit would win
 * and the cloaked payload beside it would be reported at the ordinary tier.
 * Any hit the raw text did not produce means something was concealed.
 */
export function matchAcrossVariants<T>(
  text: string,
  matcher: (candidate: string) => T,
  pick: (result: T) => unknown[],
): { result: T; transforms: string[]; variantText: string } | undefined {
  const variants = textVariants(text);

  const rawResult = matcher(variants[0].text);
  const rawHits = pick(rawResult);
  const rawKeys = new Set(rawHits.map((h) => JSON.stringify(h)));

  let best: { result: T; transforms: string[]; variantText: string; count: number } | undefined =
    rawHits.length > 0
      ? { result: rawResult, transforms: [], variantText: variants[0].text, count: rawHits.length }
      : undefined;

  for (const variant of variants.slice(1)) {
    const result = matcher(variant.text);
    const hits = pick(result);
    if (hits.length === 0) continue;

    const revealsNew = hits.some((h) => !rawKeys.has(JSON.stringify(h)));
    if (!revealsNew) continue;

    // Prefer the variant exposing the most, so a doubly-cloaked payload wins
    // over one that only partially deobfuscates.
    if (!best || best.transforms.length === 0 || hits.length > best.count) {
      best = { result, transforms: variant.transforms, variantText: variant.text, count: hits.length };
    }
  }

  return best ? { result: best.result, transforms: best.transforms, variantText: best.variantText } : undefined;
}
