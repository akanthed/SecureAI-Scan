import fs from "node:fs";
import path from "node:path";
import { textVariants } from "./deobfuscate.js";
import { stripBom } from "../utils/text.js";

/**
 * Skill *bundle* traversal and capability analysis.
 *
 * A published Agent Skill is a directory, not a file: SKILL.md is only the
 * part the agent reads first. Everything beside it — scripts, assets, docs,
 * data blobs — is equally available to the agent once the skill fires.
 *
 * "Cloak and Detonate" (arXiv:2607.02357) calls the resulting attacks
 * *disperse* operators, and they beat every scanner surveyed because those
 * scanners only ever parsed SKILL.md:
 *
 *   per-file extraction     payload moved to a helper the skill sources
 *   directory relocation    scripts/x.sh -> build/x.sh   (skipped dir)
 *   extension renaming      x.sh -> x.txt                (off the whitelist)
 *   SFS packing             XOR/base64 payload in .git/skillpack.dat
 *
 * Separately, Gecko Security demonstrated the same idea with `*.test.ts`
 * files: scanners skip them, but Jest and Vitest auto-discover and execute
 * them on `npm test`.
 *
 * So the traversal below deliberately walks directories and file extensions
 * that the rest of this scanner skips. This is a *scoped* exception to the
 * project-wide isTestFilePath convention: inside a skill bundle, a file being
 * named like a test or living under build/ is not a reason for lower trust —
 * it is the documented hiding place.
 */

/** Directories never worth walking even inside a bundle: enormous, and covered by the dependency guard. */
const HARD_SKIP_DIRS = new Set(["node_modules", ".venv", "venv", "__pycache__", ".mypy_cache", ".pytest_cache"]);

/**
 * Entries git itself creates directly under `.git/`. Anything under `.git/`
 * that is NOT one of these is foreign — nothing in normal use writes there.
 * That makes `.git/` the one directory where mere *presence* of an unexpected
 * file is meaningful, which is precisely the SFS packing hiding spot.
 */
const GIT_INTERNAL_ENTRIES = new Set([
  "head", "orig_head", "fetch_head", "merge_head", "cherry_pick_head", "revert_head", "bisect_head",
  "rebase_head", "auto_merge", "config", "description", "index", "packed-refs", "commit_editmsg",
  "merge_msg", "merge_mode", "squash_msg", "tag_editmsg", "notes_merge_ref", "shallow", "commondir",
  "gitdir", "superproject", "sparse-checkout", "gitattributes", "hooks", "info", "logs", "objects",
  "refs", "branches", "worktrees", "modules", "lfs", "rebase-merge", "rebase-apply", "sequencer",
  "filter-repo", "fsmonitor--daemon", "annex", "hooks-disabled",
]);

/**
 * Transient and tool-generated files git (or a git GUI) writes under `.git/`.
 * Matched in addition to the name list above so a scan that happens to run
 * during a concurrent git operation does not report `index.lock` as a staged
 * payload — the whole value of the `.git/` check is that a hit there means
 * something, so it must not fire on ordinary churn.
 */
const GIT_TRANSIENT_FILE = /(?:\.(?:lock|pid|log|pack|idx|rev)$|^(?:bisect|rebase|quilt|notes|sourcetree|ms-persist)[_.-]|^gc\.|^\.)/i;

function isGitInternalName(name: string): boolean {
  return GIT_INTERNAL_ENTRIES.has(name.toLowerCase()) || GIT_TRANSIENT_FILE.test(name);
}

export interface BundleFile {
  /** Path relative to the repository root, using the platform separator. */
  relPath: string;
  /** Path relative to the skill bundle root, always forward-slashed. */
  bundlePath: string;
  content: string;
  sizeBytes: number;
  /** True when the file lives under a `.git/` directory but is not a git internal. */
  foreignInGitDir: boolean;
  /** True when the bytes do not look like text (binary or encrypted blob). */
  binary: boolean;
  /** True when the bytes start with a recognized container-format magic number (gzip, zip, png, pdf, …). */
  knownBinaryFormat: boolean;
}

export interface SkillBundle {
  /** Absolute path of the directory containing SKILL.md. */
  dir: string;
  /** SKILL.md path relative to the repository root. */
  skillRelPath: string;
  skillRaw: string;
  /** Every other file in the bundle. */
  files: BundleFile[];
}

const MAX_FILE_BYTES = 512 * 1024;
const MAX_FILES_PER_BUNDLE = 400;

function looksBinary(buffer: Buffer): boolean {
  const sample = buffer.subarray(0, 4096);
  if (sample.includes(0)) return true;
  let nonPrintable = 0;
  for (const byte of sample) {
    // Tab, LF, CR and the printable ASCII/UTF-8 lead range are fine.
    if (byte === 9 || byte === 10 || byte === 13) continue;
    if (byte < 32 || byte === 127) nonPrintable++;
  }
  return sample.length > 0 && nonPrintable / sample.length > 0.1;
}

/**
 * Magic-byte signatures for common binary formats a skill can legitimately
 * ship: archives, images, fonts, PDFs, WebAssembly. Checked against the raw
 * buffer, not the extension — an attacker can rename a file, but cannot make
 * an XOR-encrypted or base64-armoured payload start with a real gzip/zip
 * header, because those formats are self-describing container structures a
 * standard tool can parse. This is the actual distinguishing feature between
 * "real compressed asset" and "opaque staged payload": one has verifiable
 * structure, the other exists only to be decoded by a script the skill
 * ships alongside it.
 */
const BINARY_MAGIC: Array<{ bytes: number[]; label: string }> = [
  { bytes: [0x1f, 0x8b], label: "gzip" },
  { bytes: [0x50, 0x4b, 0x03, 0x04], label: "zip/local" },
  { bytes: [0x50, 0x4b, 0x05, 0x06], label: "zip/empty" },
  { bytes: [0x50, 0x4b, 0x07, 0x08], label: "zip/spanned" },
  { bytes: [0x42, 0x5a, 0x68], label: "bzip2" },
  { bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], label: "xz" },
  { bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], label: "7z" },
  { bytes: [0x89, 0x50, 0x4e, 0x47], label: "png" },
  { bytes: [0xff, 0xd8, 0xff], label: "jpeg" },
  { bytes: [0x25, 0x50, 0x44, 0x46], label: "pdf" },
  { bytes: [0x00, 0x61, 0x73, 0x6d], label: "wasm" },
  { bytes: [0x47, 0x49, 0x46, 0x38], label: "gif" },
];

function hasKnownBinaryMagic(buffer: Buffer): boolean {
  return BINARY_MAGIC.some(
    ({ bytes }) => buffer.length >= bytes.length && bytes.every((b, i) => buffer[i] === b),
  );
}

/**
 * Shannon entropy in bits per character. Used only as one input to the
 * opaque-blob check — never on its own, since minified JS and lockfiles are
 * legitimately high-entropy.
 */
export function shannonEntropy(text: string): number {
  if (text.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of text) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / text.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Walk one skill bundle directory, collecting every readable file except SKILL.md itself. */
function collectBundleFiles(bundleDir: string, rootPath: string, skillAbsPath: string): BundleFile[] {
  const files: BundleFile[] = [];

  function walk(dir: string, depth: number, insideGitDir: boolean) {
    if (depth > 8 || files.length >= MAX_FILES_PER_BUNDLE) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (files.length >= MAX_FILES_PER_BUNDLE) return;
      const full = path.join(dir, entry.name);

      if (entry.isDirectory()) {
        if (HARD_SKIP_DIRS.has(entry.name)) continue;
        // A nested SKILL.md starts its own bundle; don't absorb it into this one.
        if (fs.existsSync(path.join(full, "SKILL.md"))) continue;
        // Inside .git, descend only into non-internal directories — walking
        // objects/ or refs/ would be thousands of useless files. This must not
        // apply to the ".git" entry itself: GIT_TRANSIENT_FILE's `^\.` catch-all
        // (meant for hidden files written inside .git) also matches the literal
        // name ".git", which previously skipped the directory before ever
        // descending into it.
        if (insideGitDir && isGitInternalName(entry.name)) continue;
        const nowInGit = insideGitDir || entry.name === ".git";
        walk(full, depth + 1, nowInGit);
        continue;
      }

      if (!entry.isFile()) continue;
      if (full === skillAbsPath) continue;
      if (insideGitDir && isGitInternalName(entry.name)) continue;

      let stat: fs.Stats;
      try {
        stat = fs.statSync(full);
      } catch {
        continue;
      }

      let buffer: Buffer;
      try {
        // Read only the head of oversized files: a size cap that skips them
        // entirely is itself an evasion ("size padding" in the paper).
        if (stat.size > MAX_FILE_BYTES) {
          const fd = fs.openSync(full, "r");
          buffer = Buffer.alloc(MAX_FILE_BYTES);
          fs.readSync(fd, buffer, 0, MAX_FILE_BYTES, 0);
          fs.closeSync(fd);
        } else {
          buffer = fs.readFileSync(full);
        }
      } catch {
        continue;
      }

      files.push({
        relPath: path.relative(rootPath, full),
        bundlePath: path.relative(bundleDir, full).replace(/\\/g, "/"),
        content: stripBom(buffer.toString("utf-8")),
        sizeBytes: stat.size,
        foreignInGitDir: insideGitDir,
        binary: looksBinary(buffer),
        knownBinaryFormat: hasKnownBinaryMagic(buffer),
      });
    }
  }

  walk(bundleDir, 0, false);
  return files;
}

/** Discover every skill bundle under `rootPath`. */
export function findSkillBundles(rootPath: string, skipPaths?: string[]): SkillBundle[] {
  const resolvedRoot = path.resolve(rootPath);
  const skips = (skipPaths ?? []).map((p) => path.resolve(resolvedRoot, p));
  const bundles: SkillBundle[] = [];

  function walk(dir: string, depth: number) {
    if (depth > 10) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    const skillPath = path.join(dir, "SKILL.md");
    if (entries.some((e) => e.isFile() && e.name === "SKILL.md")) {
      let raw: string;
      try {
        raw = fs.readFileSync(skillPath, "utf-8");
        bundles.push({
          dir,
          skillRelPath: path.relative(resolvedRoot, skillPath),
          skillRaw: stripBom(raw),
          files: collectBundleFiles(dir, resolvedRoot, skillPath),
        });
      } catch {
        /* unreadable SKILL.md — nothing to analyze */
      }
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const full = path.join(dir, entry.name);
      if (skips.some((s) => full === s || full.startsWith(s + path.sep))) continue;
      if (HARD_SKIP_DIRS.has(entry.name)) continue;
      // Above a bundle, `.git` and build output are ordinary repo furniture
      // and contain no skills; inside a bundle they are walked by
      // collectBundleFiles, which is where the interesting case lives.
      if (entry.name === ".git" || entry.name === ".next") continue;
      walk(full, depth + 1);
    }
  }

  walk(resolvedRoot, 0);
  return bundles;
}

// ---------------------------------------------------------------------------
// Capability analysis
// ---------------------------------------------------------------------------

export type CapabilityKind = "credential-access" | "network-egress" | "remote-code-exec";

export interface CapabilityHit {
  kind: CapabilityKind;
  /** The concrete matched text — always a specific path/URL/command, never a bare keyword. */
  match: string;
  /** 1-based line within the file. */
  line: number;
  /** Deobfuscation steps that were required to expose the match. */
  transforms: string[];
}

/**
 * Concrete credential *locations*. Every pattern is a filesystem path with a
 * directory component, not a word like "token" or "secret" — per the evidence
 * contract, a bare keyword can never justify a finding, but `~/.aws/credentials`
 * has no innocent reading in a skill bundle.
 */
// Every unbounded `[\w./\\-]*`-style prefix below is capped at {0,40}. An
// unbounded quantifier immediately before a suffix that usually doesn't
// match is classic catastrophic-backtracking shape: the regex engine tries
// every prefix length at every starting offset, which is O(n^2) on a large
// file (a big minified bundle, a lockfile) that happens to contain long runs
// of word/path characters but never the actual suffix — exactly the content
// a skill bundle's companion files are full of. A real credential path is
// never remotely close to 40 characters of prefix, so the cap costs nothing.
const CREDENTIAL_PATTERNS: RegExp[] = [
  /~?[\w./\\-]{0,40}\.aws[/\\]credentials/i,
  /~?[\w./\\-]{0,40}\.ssh[/\\]id_(?:rsa|dsa|ecdsa|ed25519)/i,
  /~?[\w./\\-]{0,40}\.config[/\\]gh[/\\]hosts\.yml/i,
  /~?[\w./\\-]{0,40}\.docker[/\\]config\.json/i,
  /~?[\w./\\-]{0,40}\.kube[/\\]config\b/i,
  /~?[\w./\\-]{0,40}\.netrc\b/i,
  /~?[\w./\\-]{0,40}\.npmrc\b/i,
  /~?[\w./\\-]{0,40}\.gnupg[/\\]/i,
  /Library[/\\]Keychains[/\\]/i,
  /~?[\w./\\-]{0,40}\.config[/\\](?:claude|anthropic|openai)[/\\][\w.-]{0,40}(?:auth|credential|token|key)[\w.-]{0,20}/i,
  /\bAppData[/\\]Roaming[/\\][\w-]{0,40}[/\\][\w.-]{0,40}(?:credential|token)[\w.-]{0,20}/i,
];

/**
 * Bulk environment-variable *enumeration* — not a single named lookup. This
 * is structurally different from ordinary API-key usage: reading one named
 * variable (`os.environ["API_KEY"]`, `process.env.STRIPE_KEY`) is completely
 * normal and must never be flagged, since almost every app does it. Iterating
 * the *entire* environment and filtering by secret-shaped key names is the
 * documented shape of an env-harvesting payload and has no ordinary-app
 * equivalent — nothing legitimate needs to enumerate every variable to find
 * the secret-looking ones by name pattern.
 */
const ENV_ENUMERATION_PATTERNS: RegExp[] = [
  /\bos\.environ\.(?:items|keys|values)\s*\(\s*\)/,
  /\bfor\s+\w+(?:\s*,\s*\w+)?\s+in\s+os\.environ\b/,
  /\bdict\s*\(\s*os\.environ\s*\)/,
  /\bObject\.(?:entries|keys|values)\s*\(\s*process\.env\s*\)/,
  /\bfor\s*\(\s*(?:const|let|var)\s+\w+\s+in\s+process\.env\s*\)/,
];

/**
 * Egress to a *hardcoded external* host. Loopback, link-local, RFC-1918 and
 * the reserved documentation domains are excluded — a skill that posts to
 * localhost or example.com is a sample, not an exfiltration path.
 */
const EGRESS_COMMAND =
  /\b(?:curl|wget|http(?:ie)?|nc|ncat|scp|rsync)\b[^\n;|&]{0,120}?(https?:\/\/[^\s"'`)]+|\b\d{1,3}(?:\.\d{1,3}){3}\b)/i;
const EGRESS_CALL =
  /\b(?:requests\.(?:post|put|patch)|urllib\.request\.urlopen|httpx\.(?:post|put)|fetch|axios\.(?:post|put)|Invoke-(?:RestMethod|WebRequest))\s*\(\s*[^)]{0,160}?(https?:\/\/[^\s"'`)]+|\b\d{1,3}(?:\.\d{1,3}){3}\b)/i;

/**
 * Loopback, link-local and RFC-1918 hosts, plus the RFC 2606 reserved
 * documentation domains — matched as the *bare* domain only, never with a
 * subdomain. `example.com` in a doc snippet is a placeholder; `attacker.
 * example.com` is not — it is the standard way security fixtures and
 * adversarial examples name a stand-in external host precisely because it
 * looks realistic, and excluding every subdomain of a reserved domain would
 * blind this check to exactly that shape.
 */
const LOCAL_HOST_RE =
  /^(?:https?:\/\/)?(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1\]|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|(?:example\.(?:com|org|net)|test|invalid|local))\b/i;

/** `curl … | bash` and friends: fetch remote content and execute it directly. */
const REMOTE_EXEC_PATTERNS: RegExp[] = [
  /\b(?:curl|wget)\b[^\n]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|k|d)?sh\b/i,
  /\b(?:eval|exec|source)\b[^\n]{0,20}[$`(]{1,2}\s*(?:curl|wget)\b/i,
  /\bIn[a-z]*-Expression\b[^\n]{0,80}\b(?:Invoke-WebRequest|iwr|curl)\b/i,
  /\b(?:iwr|Invoke-WebRequest)\b[^\n]{0,120}\|\s*(?:iex|Invoke-Expression)\b/i,
  /\bpython\d?\b[^\n]{0,40}-c\b[^\n]{0,160}\burlopen\b[^\n]{0,60}\bexec\b/i,
  /\bos\.system\s*\(\s*[^)]{0,80}(?:curl|wget)\b/i,
];

function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) {
    if (text[i] === "\n") line++;
  }
  return line;
}

/**
 * A remote fetch assigned to a variable, later passed to `exec`/`eval` — the
 * two-statement form of "download code and run it". `REMOTE_EXEC_PATTERNS`
 * only catches the single-line/single-expression form (`curl … | bash`,
 * `exec($(curl …))`); real payloads more often fetch into a variable first
 * (`payload = requests.get(url).text`) and exec it several lines later,
 * often through a decode step (`exec(base64.b64decode(payload))`).
 *
 * Deliberately proximity-bound and requires the *same* variable name to
 * appear in the exec call: an unrelated `requests.get` and an unrelated
 * `eval(user_input)` elsewhere in a large file must not correlate.
 */
const FETCH_ASSIGN_RE =
  /\b(\w+)\s*=\s*(?:requests\.(?:get|post)|urllib\.request\.urlopen|httpx\.(?:get|post)|await\s+fetch)\s*\([^)\n]*\)(?:\.(?:text|content|json\(\))(?:\s*\(\s*\))?)?/g;
const EXEC_OF_RE = /\b(?:exec|eval)\s*\(/;
const FETCH_EXEC_PROXIMITY_LINES = 10;

/** Cumulative character offset of the start of each 1-based line. */
function lineOffsets(text: string): number[] {
  const offsets = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\n") offsets.push(i + 1);
  }
  return offsets;
}

/** `newVar = ...` at the start of a line — used to follow the fetched value through one or more renames. */
const SIMPLE_ASSIGN_RE = /^\s*(?:const\s+|let\s+|var\s+)?(\w+)\s*=\s*(.+)$/;

function detectFetchThenExec(text: string): Array<{ match: string; index: number }> {
  const hits: Array<{ match: string; index: number }> = [];
  const lines = text.split(/\r?\n/);
  const offsets = lineOffsets(text);
  const assigns: Array<{ varName: string; line: number }> = [];
  let m: RegExpExecArray | null;
  FETCH_ASSIGN_RE.lastIndex = 0;
  while ((m = FETCH_ASSIGN_RE.exec(text))) {
    assigns.push({ varName: m[1], line: lineOf(text, m.index) });
  }

  for (const { varName, line } of assigns) {
    // Small taint set: the fetched variable, plus anything it gets renamed or
    // wrapped into (payload -> decoded -> ...) within the proximity window.
    // Mirrors the fixpoint variable propagation the Python AI001 rule already
    // uses — a single-hop rename (`decoded = base64.b64decode(payload)`)
    // must not silently break the fetch->exec link.
    const tainted = new Set([varName]);
    const wordRe = (name: string) => new RegExp(`\\b${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\b`);

    for (let l = line; l < Math.min(lines.length, line + FETCH_EXEC_PROXIMITY_LINES); l++) {
      const candidate = lines[l - 1] ?? "";
      if (EXEC_OF_RE.test(candidate) && [...tainted].some((t) => wordRe(t).test(candidate))) {
        hits.push({
          match: `${lines[line - 1]?.trim() ?? ""} … ${candidate.trim()}`,
          index: offsets[l - 1] ?? 0,
        });
        break;
      }
      if (l === line) continue; // the fetch-assignment line itself is not a rename source
      const assign = SIMPLE_ASSIGN_RE.exec(candidate);
      if (assign && [...tainted].some((t) => wordRe(t).test(assign[2]))) {
        tainted.add(assign[1]);
      }
    }
  }
  return hits;
}

/**
 * Detect capabilities in a file's text, retrying across deobfuscated variants
 * so homoglyph/zero-width/splice-cloaked commands are still found.
 *
 * Line numbers are resolved against the raw text where possible; for variants
 * that shift offsets (the intra-word join) the reported line is the best
 * available approximation, which is acceptable since the file is flagged as a
 * whole.
 */
export function detectCapabilities(text: string): CapabilityHit[] {
  const hits: CapabilityHit[] = [];
  const seen = new Set<string>();

  for (const variant of textVariants(text)) {
    const add = (kind: CapabilityKind, match: string, index: number) => {
      const key = `${kind}:${match}`;
      if (seen.has(key)) return;
      seen.add(key);
      hits.push({ kind, match: match.slice(0, 120), line: lineOf(variant.text, index), transforms: variant.transforms });
    };

    for (const re of [...CREDENTIAL_PATTERNS, ...ENV_ENUMERATION_PATTERNS]) {
      const m = re.exec(variant.text);
      if (m) add("credential-access", m[0], m.index);
    }

    for (const re of [EGRESS_COMMAND, EGRESS_CALL]) {
      const m = re.exec(variant.text);
      if (m && !LOCAL_HOST_RE.test(m[1] ?? "")) add("network-egress", m[0], m.index);
    }

    for (const re of REMOTE_EXEC_PATTERNS) {
      const m = re.exec(variant.text);
      if (m) add("remote-code-exec", m[0], m.index);
    }

    for (const hit of detectFetchThenExec(variant.text)) {
      add("remote-code-exec", hit.match, hit.index);
    }
  }

  return hits;
}

// ---------------------------------------------------------------------------
// Self-extracting / staged payload analysis
// ---------------------------------------------------------------------------

/**
 * Instructions telling the agent to decode, unpack or materialize something
 * before running it — the visible half of an SFS-packed skill. On its own
 * this is only suggestive (plenty of legitimate skills unzip a fixture), so
 * callers require a matching opaque blob in the same bundle.
 */
const UNPACK_DIRECTIVES: Array<{ re: RegExp; label: string }> = [
  { re: /\bbase64\s+(?:-d|--decode|-D)\b/i, label: "base64 decode" },
  { re: /\bopenssl\s+enc\b[^\n]{0,80}\B-d\b/i, label: "openssl decrypt" },
  { re: /\b(?:gpg|gpg2)\b[^\n]{0,60}--decrypt\b/i, label: "gpg decrypt" },
  { re: /\b(?:atob|b64decode|b64_decode|from_?base64)\s*\(/i, label: "base64 decode call" },
  { re: /\btar\s+(?:-)?[xz]{1,3}f?\b/i, label: "tar extract" },
  { re: /\b(?:unzip|gunzip|zcat|7z\s+x|Expand-Archive)\b/i, label: "archive extract" },
  // A bare [0-7]*7[0-7]* (any octal run containing a 7) has the digit '7'
  // inside its own repeated character class — ambiguous-split backtracking
  // on a run with no 7 at all. {3,4} covers the realistic chmod-permission
  // shapes (777, 0755, ...) without the self-overlap.
  { re: /\bchmod\s+(?:\+x|[0-7]{3,4})\b/i, label: "make executable" },
  { re: /\b(?:eval|exec|source|Invoke-Expression|iex)\b[^\n]{0,20}[$`(]{1,2}\s*(?:cat|type|Get-Content)\b/i, label: "execute file contents" },
  { re: /\bXOR\b[^\n]{0,60}\b(?:decrypt|decode|key)\b/i, label: "XOR decode" },
];

export interface UnpackDirective {
  label: string;
  match: string;
  line: number;
  transforms: string[];
}

/** Unpack/decode instructions found anywhere in the given text. */
export function detectUnpackDirectives(text: string): UnpackDirective[] {
  const found: UnpackDirective[] = [];
  const seen = new Set<string>();
  for (const variant of textVariants(text)) {
    for (const { re, label } of UNPACK_DIRECTIVES) {
      const m = re.exec(variant.text);
      if (!m || seen.has(label)) continue;
      seen.add(label);
      found.push({ label, match: m[0].slice(0, 80), line: lineOf(variant.text, m.index), transforms: variant.transforms });
    }
  }
  return found;
}

/**
 * Whether a bundle file is an opaque data blob: content a human reviewer
 * cannot read and a build step did not obviously produce.
 *
 * Legitimate high-entropy text files (minified bundles, lockfiles, source
 * maps, certificates) are excluded by extension and by content markers, since
 * they are readable-in-principle artifacts with a known provenance.
 */
const KNOWN_OPAQUE_BUT_LEGITIMATE = /\.(?:png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|eot|pdf|mp[34]|wav|zip|whl|so|dylib|wasm|min\.js|min\.css|map|lock|pem|crt|cer|key|pyc|class|node)$/i;
const TEXT_ARTIFACT_MARKERS = /-----BEGIN |sourceMappingURL|"lockfileVersion"|^\{\s*"version"/m;

export function isOpaqueBlob(file: BundleFile): boolean {
  if (file.content.length < 256) return false;
  if (KNOWN_OPAQUE_BUT_LEGITIMATE.test(file.bundlePath)) return false;
  if (TEXT_ARTIFACT_MARKERS.test(file.content.slice(0, 2048))) return false;
  // A real gzip/zip/png/pdf/wasm header is verifiable container structure —
  // a standard tool parses it, unlike an XOR/base64 blob that exists only to
  // be decoded by a script the skill ships beside it.
  if (file.knownBinaryFormat) return false;

  if (file.binary) return true;

  // A long unbroken run of base64/hex with no whitespace or natural-language
  // structure. Real prose, code and config all break far sooner than this.
  const longRun = /[A-Za-z0-9+/=]{512,}|[0-9a-fA-F]{1024,}/.test(file.content.replace(/\s+/g, ""));
  if (longRun && shannonEntropy(file.content.slice(0, 4096)) > 4.5) return true;

  return false;
}
