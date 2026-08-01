# Changelog

## 0.6.1 — 2026-08-01

### Fixed
- **DEP001 flagged every scoped npm package (`@types/node`, `@anthropic-ai/*`, `@vercel/*`, ...) as "not found in npm."** `isReasonablePackageName`'s sanity-check regex had no `/`, so any scoped name was rejected before the registry was ever queried, always resolving to a false "not found." Found by running the scanner against its own `package.json`. Fixed the regex to accept an optional `@scope/` prefix; added a permanent fixture in `test/dependency-guard.test.js`.

### Added
- Marketing/discoverability source assets (`mcp-attack-diagram.png`, `rag-poisoning-diagram.png`) for upcoming Dev.to articles on MCP tool poisoning and RAG data poisoning. The demo GIF and social preview card are staged but held back from this release pending compression/regeneration — see `MARKETING.md`.

## 0.6.0 — 2026-07-28

Evasion-resistant Agent Skill scanning. In July 2026, [*Cloak and Detonate*](https://arxiv.org/abs/2607.02357) (arXiv:2607.02357) showed that nine published skill scanners could be bypassed by >80% (structural obfuscation) and ≥90% (self-extracting packing) using transformations that preserve the payload exactly; separately, Gecko Security demonstrated an exfiltration payload hidden in a `*.test.ts` file that every public scanner skipped. SecureAI-Scan v0.5.0 was vulnerable to all of these. This release closes each published technique, and was additionally validated against two real-world corpora added to `scripts/regression-scan.js`: the canonical [anthropics/skills](https://github.com/anthropics/skills) repo (18 real skill bundles, zero findings — a pure precision check) and [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)'s own labeled eval corpus (20 skills under `evals/`, each with an `_expected.json` verdict and a directory literally named `malicious/` or `safe/`) — a rare case where a real-world repo doubles as a recall check, not just a precision one. Result: 6/6 in-scope malicious fixtures correctly flagged, zero findings on any fixture labeled safe.

### Added
- **Python AST migration spike (`spike/python-ast-poc/`)** — not part of the shipped package (`tree-sitter-python`/`web-tree-sitter` are `devDependencies` only). Confirms `web-tree-sitter` + `tree-sitter-python`'s bundled `.wasm` grammar parses real Python with zero native compilation, and ports enough of AI001 to demonstrate a concrete, real gap in the current regex scanner: `self.user_message = request.json[...]` (any class-based handler — Flask `MethodView`, FastAPI DI classes) is completely invisible to `collectRequestTaintedVars`, which only recognizes bare-identifier assignment targets, even at `--paranoid`. The AST-based POC catches it with no special-casing. See `ROADMAP.md` for the full findings and effort estimate.
- **`secureai-scan skill <target>` / `secureai-scan mcp <target>`** — the pre-install wedge: fetch and scan a single Agent Skill or MCP server *before* trusting it, with no clone, no config, and nothing fetched ever executed. `target` accepts a local path, a full git URL, a GitHub `owner/repo` shorthand, or (for `mcp`) a bare npm package name. npm targets are downloaded with `npm pack` — the tarball only, no `install`, no lifecycle scripts; git targets with `git clone --depth 1`. New module: `src/scanner/fetch-target.ts`.
- **MCP server: `scan_untrusted_target` tool** — the same fetch-and-scan capability exposed to Claude itself via the bundled MCP server (`mcp-server/index.js`), so an agent can check a skill or MCP server before recommending or installing it, from inside the conversation. `skills/secureai-scan/SKILL.md` updated to use this flow instead of its previous "clone it first" instructions.
- **Deobfuscation layer (`src/scanner/deobfuscate.ts`)** — content checks now match against normalized *variants* of the text rather than one fixed byte sequence: zero-width/bidi stripping, Unicode homoglyph folding, spliced-string-literal joining (`'cu' + 'rl'`), and intra-word line-break joining. Transforms are applied cumulatively, so a payload cloaked with two techniques at once is still recovered.
  - **A match found only after deobfuscation is promoted to `proven`, not demoted.** Ordinary prose does not contain a zero-width joiner inside "ignore previous instructions"; the concealment is affirmative evidence of intent. Comparison is against the *set* of raw matches, so an attacker cannot mask the signal by leaving one innocuous phrase in the clear.
- **Bundle-level skill scanning (`src/scanner/skill-bundle.ts`)** — a skill is now scanned as a *directory*, not just its `SKILL.md`. Companion files are read regardless of directory (`build/`, `docs/`, `assets/`, `.git/`), extension, or test-file naming, and oversized files are head-read rather than skipped. This closes the paper's *disperse* operators (per-file extraction, directory relocation, extension renaming, size padding) and the Gecko test-file vector.
- **SKL004 — staged / self-extracting payload** (critical, proven). Fires on an opaque high-entropy blob plus an unpack directive (`base64 -d`, `openssl enc -d`, `chmod +x`, …) that *references that blob by name*, or on any non-git file placed under a bundle's `.git/` directory — the exact hiding place used by the paper's SFS packing attack.
- **SKL005 — credential exfiltration / remote code execution in a bundle** (critical). Fires on a concrete credential *path* (`~/.aws/credentials`, `~/.ssh/id_ed25519`, `~/.kube/config`, …) or bulk environment-variable enumeration, plus egress to a hardcoded non-local host **within 25 lines in the same file**, or on `curl … | bash`-style remote execution (including a fetch-then-exec split across statements) alone. Evidence drops to `likely` when the skill's own description discloses the behaviour.
- **`test/deobfuscate.test.js`** — 14 tests covering each transformation in the SkillCloak taxonomy end-to-end, plus the `.git/` staging case (which cannot live in `test-fixtures/`, since git will not track a nested `.git/`).

### Fixed
Three false positives found by running the new rules against real public skill bundles — the 14 `SKILL.md` files shipped in [vercel/ai](https://github.com/vercel/ai):

- **SKL002 flagged ordinary security advice as a credential-read instruction** — the pattern accepted a bare `api[ _]?keys?` alternative, so the AI SDK's own guidance "Load API keys securely using `loadApiKey`" fired at `likely`. Every alternative now requires a concrete credential *location* (a path or a filename with an extension), not an English phrase. This is the "bare keyword given undeserved evidence" failure mode called out in `CLAUDE.md`.
- **SKL003/MCP009 matched a skill name inside a package specifier** — `\b` does not help when the delimiters are `-` and `/`, so a skill named `ai-sdk` matched inside every `@ai-sdk/provider-utils` reference. Names preceded by `@` or `/`, or followed by `/`, are no longer treated as references to the tool.
- **SKL003/MCP009 correlated a directive with a tool name anywhere in the document** — "Reuse tools when appropriate" 200 lines from a mention of a sibling skill was reported as shadowing. The directive and the tool name must now appear in the same sentence.

All three shapes are pinned as permanent fixtures under `test-fixtures/safe/skills/`.

Four more bugs found by running against the two new corpora above, all fixed at the root cause and locked in as permanent `test-fixtures/` cases:

- **SKL001 flagged a standard UTF-8 BOM as invisible-Unicode poisoning** — `anthropics/skills`' bundled OPC/ECMA-376 XML schemas (`.xsd` files inside the `docx`/`pptx`/`xlsx` skills) legitimately open with `U+FEFF`. Whole-bundle file reads now go through the same `stripBom` utility already used everywhere else in this codebase for JSON config reads (`src/utils/text.ts`) — a BOM is standard encoding metadata, not concealed content, and this was the one read path in the scanner that had never been routed through it.
- **SKL004 flagged a real `.tar.gz` component bundle as a staged payload** — `web-artifacts-builder`'s `shadcn-components.tar.gz`, extracted by a documented `tar -xzf` setup step, satisfied the "opaque blob + unpack directive" conjunction. `isOpaqueBlob` now checks the buffer's magic bytes (gzip/zip/bzip2/xz/7z/png/jpeg/pdf/wasm/gif) before falling back to the entropy heuristic: a real archive is a verifiable, standard container structure a normal tool parses, which an XOR/base64 payload — built only to be decoded by a script the skill ships beside it — cannot fake.
- **SKL005 missed an env-var harvesting payload** (`data-exfiltration/environment-secrets` in the Cisco eval corpus) — credential detection only matched concrete file *paths*. Added a structural pattern for bulk environment enumeration (`os.environ.items()`, `for k in os.environ`, `Object.entries(process.env)`, …), deliberately requiring iteration over the *whole* environment rather than one named lookup — `os.environ["API_KEY"]` and `process.env.STRIPE_KEY` remain unflagged, since almost every app does that. The credential/egress proximity window was also widened from 15 to 25 lines: the real fixture split harvesting and exfiltration into separate function bodies 17 lines apart, still well inside the ~35-line separation of the legitimate `deploy-helper` safe fixture used to bound the widening.
- **SKL005 missed a fetch-then-exec backdoor** (`backdoor/magic-string-trigger`) — `REMOTE_EXEC_PATTERNS` only covered the single-expression form (`curl … | bash`). Added a proximity pass that finds a remote fetch assigned to a variable and follows it through one or more renames (`payload = requests.get(...).text` → `decoded = base64.b64decode(payload)` → `exec(decoded)`) within a 10-line window — the same lightweight taint-propagation idea the Python AI001 rule already uses for request-input tracking, applied here to a fetch source instead of a request source.
- **`LOCAL_HOST_RE` excluded every subdomain of `example.com`**, not just the bare RFC 2606 reserved domain — so `attacker.example.com`, the real hostname the Cisco eval corpus uses for its simulated exfiltration target, was silently treated as a documentation placeholder and never even considered for a network-egress hit. Narrowed to match the bare reserved domain only.

Three more bugs found by hand-triaging all 40 findings from a full scan of [vercel/ai](https://github.com/vercel/ai) (5,511 files) — none specific to the skill rules above, all in shared logic used across many rules, all fixed at the root and pinned as permanent fixtures:

- **`resolveLlmSink`'s resolved-module branch treated any call reaching an LLM SDK package as a model invocation, with no check on the method name** — `GENERATION_METHODS` existed for exactly this purpose but was only wired into the unresolved-name fallback path. Flagged `isToolUIPart()` (a type guard the `ai` package exports alongside `generateText`) as an LLM call inside `vercel/ai`'s own TUI harness, which cascaded into 3 of the 5 sampled finding groups (AI001, AI003, AI010) once combined with `isRequestHandler`'s separate `req`/`request`-parameter-name heuristic. `GENERATION_METHODS` is now required on the resolved path too — every real SDK entry point (`generateText`, `streamText`, `chat.completions.create`, …) was already in that set, so this only removes false positives. Fixture: `test-fixtures/safe/ai_sdk_type_guard.ts`.
- **AI005's `DANGEROUS_CALLEES` includes `"query"` for SQL-injection-style sinks, colliding with `GENERATION_METHODS`'s own `"query"` entry** — `claudeSdk.query({ prompt, options })`, the Claude Agent SDK's own model invocation, was flagged as "LLM output passed to a dangerous sink" purely because of the shared bare verb. `isDangerousSink` now excludes a call that `resolveLlmSink` itself identifies as an LLM invocation, reusing the existing resolver rather than adding a second independent heuristic. Fixture: `test-fixtures/safe/agent_sdk_query.ts`.
- **`REQUEST_SOURCES`, duplicated identically across MCP002, MCP010, and VEC003, matched a bare `"params."`** — any function parameter conventionally named `params`, not necessarily HTTP request data. `assertOpenLinkParams(params: unknown)`, a URL-scheme allowlist check with nothing to do with MCP server connections, was flagged by MCP002 as "MCP server endpoint URL is constructed from user-controlled input" purely because its return object had a `url` property assigned from `params.url`. All three rules narrowed to require `req.`/`request.`/`ctx.` (which already cover genuine chained access like `req.body.serverUrl` via substring matching); the bare `body.`/`query.`/`params.`/`headers.` entries are gone. MCP002 had no fixture coverage at all before this — added both `test-fixtures/vulnerable/mcp_dynamic_url.ts` (recall) and `test-fixtures/safe/url_param_validator.ts` (precision).

Result: all 40 original findings confirmed false positives; a full re-scan of `vercel/ai` after all three fixes reports zero findings.

### Fixed (infrastructure)
- **`mcp-server/index.js` could not start on Windows at all** — every dynamic `import()` used a raw resolved path (`` `${distRoot}/scanner/scan.js` ``), which Node's ESM loader rejects for absolute Windows paths (`ERR_UNSUPPORTED_ESM_URL_SCHEME` — a `file://` URL is required). This meant none of the server's tools, old or new, ever worked on Windows. Fixed by routing every dist import through `pathToFileURL`. Pre-existing bug, found while verifying the new `scan_untrusted_target` tool.
- **`fetch-target.ts`'s npm path failed on Windows two different ways** — `execFileSync("npm", …)` doesn't work at all without `shell: true` (`npm` is `npm.cmd`, a batch file, which Node's ESM `execFileSync` cannot invoke directly — confirmed by testing: fails with `ENOENT`/`EINVAL` either way), and the subsequent `tar -xzf` extraction failed with "Cannot connect to C: resolve failed" — GNU tar (as shipped via Git for Windows) interprets an absolute `C:\...` path as a `host:path` remote-archive spec unless given `--force-local`, and separately mangles backslash-heavy arguments when invoked through a bash-launched Node process, requiring forward-slash paths. Both fixes are gated to `process.platform === "win32"` — `--force-local` is a GNU tar flag that BSD tar (macOS's default) does not recognize.

## 0.5.0 — 2026-07-23

### Added
- **Agent Skill scanning (SKILL.md)** — new `skill-scanner.ts` walks the repo for `SKILL.md` files (Claude Skills and equivalents) and reuses the same tool-poisoning checks already applied to MCP tool metadata:
  - **SKL001** — invisible/bidi Unicode hidden in a skill's frontmatter or body
  - **SKL002** — agent-directed injection phrasing in a skill's frontmatter or body
  - **SKL003** — a skill's content steers when/how a *different* skill is invoked (cross-skill shadowing)
- **MCP010 — dynamic MCP server command from untrusted input** (critical, proven/likely) — flags a stdio transport's `command`/`args` built from request-derived data. The MCP stdio transport executes that command as a real OS process, so this is architecturally the same risk class as passing user input to `child_process.exec`
- **DEP003 now compares actual declared versions against advisory ranges** — previously `affectedVersions` was display-only text; an exact pinned version (`package.json`, `requirements.txt`, or an MCP config server spec) is now parsed and checked against the advisory's range via a new minimal semver utility (`src/scanner/semver.ts`). Any ambiguity (a caret/tilde range, an unparseable spec) still fails toward flagging, never toward silently clearing a finding
- `test/cli.test.js` and `test/dependency-guard.test.js` — new CLI-layer and version-gating regression tests (see hard requirements #2 and #4 in `CLAUDE.md`)

### Fixed
- **AI002 (sensitive prompt/response logging) false-positived on OAuth metadata fields** — `token_endpoint`, `tokenType`, `tokenUrl`, `tokenExpiry`, and similar `token`/`secret` compounds followed by a metadata suffix (`endpoint`, `url`, `uri`, `type`, `expiry`, `expires`, `ttl`, `issuer`, `length`) are no longer classified as leaked secret values
- **AI007 (RAG context injection) treated `chunks` as unambiguous RAG evidence** — `chunks` is an extremely common LLM streaming-response variable name (`for await (const chunk of stream)`) with nothing to do with retrieval. It's now grouped with the other ambiguous names (`context`, `contexts`, `results`) and only counts as RAG content when the enclosing function also shows an actual retrieval call
- **AI007 prompt-part extraction now reuses `getPromptParts`** instead of a rule-local ad hoc parser, and demotes evidence in matched test/example paths — consistent with the shared-helper convention the rest of the rules follow
- **AI008 (system prompt leakage)** — narrowed to multi-word phrases specific enough that ordinary prose can't collide, plus a regex for labeled secret values, instead of a raw substring search on words like "secret"/"token"
- **Windows/BOM safety** — `dependency-guard.ts`'s `package.json`/`requirements.txt` reads now go through `stripBom` before `JSON.parse`, matching the fix already applied elsewhere for DEP001–DEP003

## 0.4.1 — 2026-07-21

### Fixed
- **Python LLM-call detection was missing entire SDKs** — `litellm.completion`/`acompletion`/`text_completion`, generic `.invoke_model(`/`.converse(` (Bedrock clients not literally named `bedrock`), Cohere `co.chat(`, Mistral `.chat.complete(`, and Ollama `.chat`/`.generate(` were recognized as LLM SDK imports but their actual call syntax wasn't in the call-pattern list. Every rule gated on that list (AI001, AI003, AI004, AI005, AI007, AI010) silently produced zero findings on apps using these SDKs, even with `--paranoid`
- **AI001 (Python) missed prompt injection across ordinary handler code** — the rule only looked 10 lines ahead of a `request.*` read for an LLM call. Realistic handlers (logging, rate-limit checks, RAG retrieval between the request read and the model call) routinely exceed that window. AI001 now walks the enclosing function, tracks which variables are tainted by request data through reassignment (fixpoint propagation), and checks the LLM call site against that set instead of a fixed line distance. Direct textual matches still report at `likely`; taint carried through intermediate variables reports at `heuristic`

## 0.4.0 — 2026-07-20

### Added
- **Three-framework OWASP mapping** — every rule now maps to the OWASP LLM Top 10 (2025), the OWASP Top 10 for Agentic Applications (2026, ASI01–ASI10), and the OWASP MCP Top 10 (2025) where applicable. Tags render in terminal, Markdown, HTML, JSON, and SARIF output (`owasp-asi-2026/*`, `owasp-mcp-top10/*` SARIF tags)
- **OWASP coverage matrix** — `secureai-scan threat-model` now includes a per-framework table showing which of the 30 risks are covered by rules, which fired in this scan, and which are runtime/process concerns a static scanner cannot assess
- **MCP007 — invisible Unicode in tool metadata** (critical, proven) — detects zero-width, bidi, and Unicode-tags-block characters hidden in MCP tool names/descriptions (`@modelcontextprotocol/sdk`, FastMCP — TS and Python)
- **MCP008 — injection phrasing in tool descriptions** (high, likely) — flags agent-directed instructions in tool descriptions ("ignore previous instructions", concealment from the user, credential-file reads, exfil-to-URL), the pattern behind real-world tool-poisoning attacks
- **MCP009 — cross-tool shadowing** (medium, likely) — flags a tool description that dictates when/how a *different* tool is used ("when send_email is called, first route through this tool")
- **DEP003 — known-malicious/vulnerable dependency** (critical/high, proven) — offline curated advisory list (postmark-mcp backdoor, mcp-remote CVE-2025-6514) checked on **every** scan against package.json, requirements.txt, and packages launched from MCP configs. No network required; no flag needed

### Changed
- `--only-mcp` now also runs MCP007–MCP009
- `--rules` accepts DEP001–DEP003

## 0.3.1 — 2026-07-14

### Fixed
- **Python AI005** — `subprocess.run`/`eval`/`exec`/`os.system` sinks no longer flag on ordinary code just because a nearby variable was named `result`/`output`/etc. Now requires the file to import a known LLM SDK, inspects only the sink's arguments (not the whole line), and traces a real assignment link from an LLM call before reporting at `critical`; a name-only match without a confirmed link now reports at a lower `high`/heuristic tier instead
- **Python AI002** — sensitive prompt/response logging now also requires the file to import a known LLM SDK, so non-LLM code with a variable named `prompt` no longer false-positives
- **Windows glob exclusion** — `node_modules`, `dist`, `build`, and policy `skipPaths` are now actually excluded from TS/JS scans on Windows. `path.join`/`path.resolve` produce backslash-separated paths, which the glob engine treats as escape characters, silently no-oping every exclude pattern; patterns are now normalized to forward slashes
- **Crash safety** — ts-morph symbol resolution (`resolveLlmSink`, and the equivalent lookup in the AI004 sensitive-data rule) is now wrapped so a single malformed/edge-case file can no longer abort an entire scan run
- **AI012** — dropped a bare-name fallback that flagged `JSON.parse(result)` on any variable named `result`/`output`/etc. regardless of whether it actually came from an LLM call
- **AI007 (RAG context injection)** — generic names like `context`/`results` now only count as retrieved RAG content when the enclosing function also shows an actual retrieval call (e.g. `similaritySearch`); unambiguous names (`docs`, `chunks`, `retrievedDocs`, ...) still fire directly. Ambiguous-name matches report at heuristic tier
- **AI010 (indirect prompt injection)** — fetch-derived variable detection now checks actual call-expression/property-access nodes instead of substring-matching whole initializer text, so values like `{ fetch: true }` or `prefetchedIds` no longer false-positive
- **VEC001 / VEC004** — `supabase`/`opensearch` clients (also used for ordinary, non-vector DB reads/writes) now require an explicit vector/embedding signal before flagging; dropped bare `metadata` as sufficient evidence of tenant/access-control filtering
- **AI-BOM** — model-identifier matching (esp. short IDs like `o1`/`o3`/`o4`) is now scoped to string-literal contents instead of the whole file, so ordinary variable/loop names no longer show up as "OpenAI model referenced"
- **DEP002** — added the missing `RULE_CATALOG` entry; findings no longer render with blank OWASP/fix tags in Markdown, HTML, and SARIF output
- **Report snippets** — the source-line cache no longer folds path case on case-sensitive filesystems (Linux/macOS), which could have let two same-name-different-case files share cached content
- **Dependency guard** — a registry-unreachable network failure now prints a one-line warning instead of silently no-opping DEP001 for the whole run (still fails open on the individual check, to avoid a manufactured false positive from a network blip)

### Note for CI users
A few of the fixes above intentionally change scan output: some previously-`critical` AI005 findings now report at a lower tier when there's no confirmed dataflow link, and some previously-flagged AI007/VEC001/VEC004/AI010/AI012 cases no longer fire at all. If you pin `--fail-on critical` in CI, expect your finding count to drop on upgrade — that's the intended effect of removing false positives, not a regression.

## 0.2.1 — 2026-06-07

### Added
- **Python support** — 11 of the 19 rules now scan `.py` files (AI001–AI007, AI010, VEC001, VEC003, MCP001). Covers LangChain, OpenAI SDK, Anthropic SDK, Flask, FastAPI, Chroma, Pinecone, Weaviate, and more
- **MCP server** (`mcp-server/index.js`) — exposes SecureAI-Scan as native Claude tools via the Model Context Protocol. Three tools: `scan_repository`, `explain_rule`, `evaluate_prompt`. Works with Claude Desktop and any MCP-compatible client
- **`GPT_PROMPT.md`** — ready-to-paste system prompt for creating a ChatGPT Custom GPT on the GPT Store
- **`VISIBILITY.md`** — step-by-step guide for getting SecureAI-Scan discovered on ChatGPT, Claude, Perplexity, npm, OWASP, and developer communities

### Improved
- CLI description and `--debug` output now show separate TS/JS and Python file counts
- `scan_repository` (programmatic API) returns `pythonFiles` alongside `scannedFiles`
- `skipPaths` and `blockedRules` from policy now apply to Python file scanning too
- README updated to cover Python examples, MCP server setup, and updated FAQ

## 0.2.0 — 2026-06-07

### Added
- **9 new security rules** — AI010, AI011, AI012, MCP001, MCP002, MCP003, VEC001, VEC002, VEC003
- **MCP rule category** — detects tool description injection, dynamic server URLs, unvalidated tool results
- **Vector/RAG rule category** — detects data poisoning, cross-tenant leakage, unbounded search
- **`secureai-scan init`** — first-time setup: creates policy file + GitHub Actions workflow + step-by-step guide
- **`secureai-scan threat-model`** — generates THREAT_MODEL.md with trust boundaries, attack scenarios, remediation priority
- **`--only-mcp`** and **`--only-vec`** scan filters (alongside existing `--only-ai`)
- **`--min-confidence <0-1>`** flag — control false-positive sensitivity (default: 0.4)
- **`--policy <file>`** flag — enforce `.secureai-policy.json` settings in CI
- **Policy file** (`.secureai-policy.json`) — declare minSeverity, minConfidence, failOnSeverity, skipPaths
- **CI exit code** — scan exits with code 1 when `failOnSeverity` threshold is breached
- **Explain coverage** — all 19 rules now have full `whyRisky`, `howExploited`, `howToFix`, and code examples

### Improved
- Confidence scoring now reduces score for test files (−0.30), nearby sanitization (−0.35), embedding-only calls (−0.40)
- Terminal output shows count of findings hidden by confidence threshold
- Contextual hints now suggest `init`, `threat-model`, and `explain` based on scan results
- CLI help text includes quick-start examples for all commands

## 0.1.6 — 2026-04-28

### Added
- Core rules: AI001 (prompt injection), AI002 (sensitive logging), AI003 (LLM before auth), AI004 (sensitive data to LLM), AI005 (unsafe output), AI006 (excessive agency), AI007 (RAG context injection), AI008 (system prompt leakage), AI009 (unbounded input)
- AI100 informational: LLM SDK usage detection
- Baseline diff mode (`--baseline`)
- HTML, Markdown, and JSON report output (`--output`)
- Dependency scanning for hallucinated/typo package names (`--check-dependencies`)
- Prompt risk evaluator (`secureai-scan prompt "<text>"`)
- Inline ignore annotations (`// secureai-ignore RULE_ID: reason`)
- `secureai-scan explain <RULE_ID>` with code examples
- Confidence scoring system
- GitHub Actions workflow example
