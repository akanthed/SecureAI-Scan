/**
 * Strips a leading UTF-8 BOM (U+FEFF) if present. Files saved by common
 * Windows tooling (PowerShell's default `utf8` encoding, some editor/.NET
 * defaults) carry one; `JSON.parse` rejects it outright, and every
 * JSON-reading call site in this codebase wraps parsing in a bare
 * try/catch that swallows the resulting SyntaxError — so an unhandled BOM
 * doesn't error, it silently produces zero findings from that file.
 */
export function stripBom(text: string): string {
  return text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
}
