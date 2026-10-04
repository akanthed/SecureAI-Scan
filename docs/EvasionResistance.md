# Evasion resistance (Agent Skill bundles)

In July 2026, two pieces of public research showed that Agent Skill scanners are trivially bypassed.

**[Cloak and Detonate](https://arxiv.org/abs/2607.02357)** (Ji, Xu, Li, Gao, Wei, Wang & Cheung — HKUST, arXiv:2607.02357) ran an adversarial study against **nine** published skill scanners using 1,613 in-the-wild malicious skills. Two attack families, both of which preserve the payload exactly:

- **Reify** — rewrite the bytes a rule matches, while the agent still reassembles the original at runtime. **>80% bypass** on most static scanners.
- **Disperse / SFS packing** — move the payload outside the rule's scope: into a directory the scanner skips, behind a renamed extension, or archived and encoded into `.git/`, with a benign cover `SKILL.md` that rebuilds it on first run. **≥90% bypass on every scanner tested**, ≥96% on most. One hybrid scanner's detection rate fell from ~99% to ~10%.

Separately, **Gecko Security** ([VentureBeat](https://venturebeat.com/security/anthropic-skill-scanners-passed-every-check-malicious-code-test-file)) shipped a payload in a `*.test.ts` file. Every public scanner skipped it — but Jest and Vitest auto-discover and execute those files on the next `npm test`.

SecureAI-Scan handles each published technique. Every row below has a corresponding test in [`test/deobfuscate.test.js`](../test/deobfuscate.test.js) or a fixture in [`test-fixtures/vulnerable/skills/`](../test-fixtures/vulnerable/skills):

| Technique (paper's name) | Example | How it's handled |
|---|---|---|
| Zero-width insertion | `Ign‍ore all pre‍vious…` | Text is matched against invisible-stripped variants |
| Confusable glyphs | `сurl` (Cyrillic `с`) | Homoglyph folding to ASCII before matching |
| Case flip | `EvAl` | All content patterns are case-insensitive |
| Variable splicing | `'cu' + 'rl'` | Adjacent string literals joined before matching |
| Per-line splitting | `ev`⏎`al(x)` | Intra-word line breaks joined as an extra variant |
| Per-file extraction | payload in a sourced helper | Whole bundle is scanned, not just `SKILL.md` |
| Directory relocation | `scripts/x.sh` → `build/x.sh` | No directory skip-list inside a bundle |
| Extension renaming | `x.sh` → `x.txt` | Files are scanned by content, not extension |
| Size padding | pad past the scanner's cap | Oversized files are head-read, never skipped |
| SFS packing | payload in `.git/skillpack.dat` | Any non-git file under a bundle's `.git/` is `proven` (SKL004) |
| Test-file staging | payload in `*.test.ts` | Bundle scanning deliberately does **not** demote test paths (SKL005) |

## This does not weaken the precision contract

Deobfuscation is usually a precision risk — more matches, more noise. Here the logic is inverted: **a match that appears only after deobfuscation is promoted to `proven`, not demoted.** Ordinary documentation does not contain a zero-width joiner inside "ignore previous instructions", nor a Cyrillic `с` inside `curl`. The concealment is itself affirmative evidence of intent.

The comparison is against the *set* of raw matches, not merely "did the raw text match at all" — otherwise an attacker could mask the signal by leaving one innocuous phrase in the clear.

The two new bundle rules fire only on conjunctions, never on a keyword:

- **SKL004** needs an opaque blob **and** an unpack directive that *references that blob by name* — a README mentioning `tar -x` next to an unrelated binary asset is not enough. Real archives (gzip/zip/png/pdf/wasm — checked by magic bytes, not extension) are never "opaque" in the first place, however they're compressed.
- **SKL005** needs a concrete credential *signal* — a path (`~/.aws/credentials`, not the word "token") or bulk environment-variable enumeration (`os.environ.items()`, not `os.environ["API_KEY"]`) — **and** egress to a hardcoded non-local host, **within 25 lines of each other in the same file**, or a remote fetch that gets executed after being reassigned through one or more renames. A publish helper that reads `~/.npmrc` in one function and calls a registry forty lines later stays clean, and reading one named env var for an API call is never flagged — both shapes are pinned as safe fixtures.

Validated against two real-world corpora, not just fixtures we wrote ourselves: **0 findings across all 18 real skill bundles in [anthropics/skills](https://github.com/anthropics/skills)** and all 14 in vercel/ai, and **6/6 correct on [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)'s labeled eval corpus** (20 skills, each with an `_expected.json` verdict) with zero false positives on anything labeled safe. See [Testing & benchmarking](Benchmarks.md).

## What this is not

Honest limitation: the paper's conclusion is that runtime detonation beats static analysis, and that is correct. An adaptive adversary who knows these rules can write a transformation they don't cover. What changes here is the *cost* of evasion — the published, currently-circulating techniques no longer work, and the obfuscation needed to defeat them now itself raises the finding's severity. **Static scanning is a filter, not a security boundary.** Treat an untrusted skill as untrusted code regardless of what any scanner says.
