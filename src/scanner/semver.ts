/**
 * Minimal semver comparison for DEP003 version-range gating. Deliberately
 * small: it only needs to answer "is this exact declared version inside the
 * advisory's affected range", not resolve npm's full range grammar.
 */

export interface SemVer {
  major: number;
  minor: number;
  patch: number;
}

/** Parses an exact `x.y.z` version, ignoring a leading `v`. Rejects anything
 * that isn't a bare exact version (ranges, wildcards, pre-release tags are
 * out of scope — callers should fail safe on `undefined`). */
export function parseExactVersion(raw: string): SemVer | undefined {
  const trimmed = raw.trim();
  const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(trimmed);
  if (!m) return undefined;
  return { major: Number(m[1]), minor: Number(m[2]), patch: Number(m[3]) };
}

function compareSemVer(a: SemVer, b: SemVer): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  return a.patch - b.patch;
}

/**
 * Does `version` (an exact semver) satisfy `range` (a comparator like
 * ">=1.0.16", "<0.1.16", possibly multiple comparators joined by spaces,
 * e.g. ">=1.0.0 <2.0.0")? Returns undefined if either side can't be parsed
 * — callers must treat that as "unknown" and fail toward flagging, not
 * toward silently clearing the finding.
 */
export function versionSatisfiesRange(version: SemVer, range: string): boolean | undefined {
  const comparators = range.trim().split(/\s+/).filter(Boolean);
  if (comparators.length === 0) return undefined;

  for (const comparator of comparators) {
    const m = /^(>=|<=|>|<|=)?\s*v?(\d+\.\d+\.\d+)$/.exec(comparator);
    if (!m) return undefined;
    const op = m[1] ?? "=";
    const bound = parseExactVersion(m[2]);
    if (!bound) return undefined;
    const cmp = compareSemVer(version, bound);
    const ok =
      op === ">=" ? cmp >= 0 : op === "<=" ? cmp <= 0 : op === ">" ? cmp > 0 : op === "<" ? cmp < 0 : cmp === 0;
    if (!ok) return false;
  }
  return true;
}
