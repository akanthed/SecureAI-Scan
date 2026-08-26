# Changelog

## 0.11.0 — 2026-08-27

Ecosystem audit of public MCP servers turns up and fixes five precision bugs, plus a pre-commit hook and a VS Code extension scaffold for the distribution roadmap.

### Fixed
Found by scanning real third-party MCP servers (upstash/context7, cloudflare/mcp-server-cloudflare, stripe/agent-toolkit, awslabs/mcp):
- **AI002** flagged secrets outside any LLM context (missing `llmFile` gate on the "secret" branch) — fired on a bcrypt hash logged in a plain demo app and a non-secret constant merely named with "KEY".
- **isTestFilePath** didn't recognize `eval(s)` as a non-production path segment, so an LLM-as-judge eval harness (vitest-evals) was scanned as a real request handler.
- **MCP001** compared a system-prompt string against a tainted variable name with a plain substring search instead of requiring a real identifier reference, producing a `proven`/critical false positive on prose that merely used the word "tools".
- **MCP009/SKL003** cross-tool-reference detection resolved all 7 residual false positives by requiring the referenced tool name to sit between the trigger word and the verb (a redirect), not merely appear anywhere in the sentence (a normal "use X for Y" mention).

### Added
- **MCP011: untrusted tool source.** Flags an MCP tool handler that fetches from an external/unauthenticated source and returns the response as the tool result with no sanitization in between — the Sentry-MCP-DSN attack shape, where the tool server itself is the injection vector rather than the tool's static name/description (MCP007/MCP008).
- **Pre-commit hook** (`.pre-commit-hooks.yaml`) — run this scanner as a pre-commit.com hook, catching findings before push instead of after.
- **VS Code extension scaffold** (`vscode-extension/`) — wraps the CLI and reports findings as Problems-panel diagnostics; local-build install only, not yet published to the Marketplace.
- Example compliance artifact (`docs/examples/THREAT_MODEL.example.md`) and a real terminal-recording demo.

### Also
- `docs/RealWorldFindings.md` updated with the full ecosystem-audit writeup.
- Roadmap corrected on competitive positioning (Invariant Labs/MCP-Scan → Snyk Agent Scan).

## 0.10.0 — 2026-08-19

Static config scanning for LiteLLM Proxy, plus six false-positive/robustness bugs found and fixed by adding a large real-world repo (BerriAI/litellm) to the regression gate.

### Added
- **LLC001–LLC003: LiteLLM Proxy `config.yaml` scanning.** New off-disk scanner (`src/scanner/litellm-config-scanner.ts`), following the same pattern as `mcp-config-scanner.ts`. Gated behind a structural check (`model_list` + `litellm_params`) so unrelated YAML files are never touched.
  - **LLC001** (`proven`, critical): a hardcoded secret in `litellm_params`/`general_settings` instead of an `os.environ/VAR_NAME` reference.
  - **LLC002** (`proven`, high): a provider `api_base` reachable over plaintext `http://` (non-localhost).
  - **LLC003** (`heuristic`, low, `--paranoid` only): no `guardrails:` section configured at all — absence of an optional control, not a proven gap.
  - New dependency: `js-yaml` (default-schema `load()`, no unsafe deserialization tags).

### Fixed
Found by adding BerriAI/litellm — the official repo, ~7,000 TS/JS files plus a large Python codebase — to `npm run regression`, specifically to get real coverage for the new LLC rules (none of the existing regression repos ship a LiteLLM proxy config):

- **LLC001 line misattribution.** Anchored findings to the first line containing the key name (`api_key`) rather than the flagged value — in a config with many `api_key:` entries, this could point at an unrelated `os.environ/` reference. Now anchors on the value itself.
- **LLC001 placeholder-value false positives.** LiteLLM's own docs/tests use dummy values like `fake-key`, `sk-lar1-demo` to demonstrate config shape. Added a placeholder-word check plus a "longest unbroken alphanumeric run" heuristic to distinguish a random credential blob from a human-typed phrase.
- **A rule crash was silently discarding every other rule's findings.** A ts-morph type-checker failure on one file (a large multi-`tsconfig.json` monorepo edge case) took down the entire scan, not just the failing rule — a scan that goes quiet instead of erroring is indistinguishable from "clean," which is worse than any false positive. Each rule's `run()` is now isolated in `scan.ts`; a failure logs a warning and the rest of the scan continues.
- **MCP001 (Python) module-scope false positive.** An admin-UI settings description containing the words "system prompt" was treated as MCP tool metadata because the scoping guard fell back to the whole file (17k lines) when the match wasn't inside a function — "the file mentions MCP somewhere" is true of nearly any file that size in a proxy codebase. Capped the module-level fallback to a small line window.
- **MCP002 (TypeScript) blanket parameter taint.** Every function parameter was treated as "user-controlled input" regardless of whether the function had anything to do with request handling, flagging a pure URL-parsing utility (`extractMCPToken(url: string)`) purely because it has a parameter named `url`. The known-vulnerable fixture never relied on this. Removed the blanket taint.
- **VEC001 (Python) `re.search` collision.** Python's stdlib `re.search(r"/vector_stores/([^/]+)/", path)` — ordinary URL-path parsing — matched as a vector-store similarity search because the regex pattern string contained the substring "vector." Excluded `re.search`/`regex.search`.
- **AI003 (Python) missed FastAPI's idiomatic auth pattern.** `Depends(...)` in a route's parameter list (the standard place FastAPI auth lives, e.g. `user: X = Depends(user_api_key_auth)`) was never checked — only the decorator and function body were. Every health-check route in litellm's own proxy was flagged as unauthenticated despite being authenticated two different ways. Now scans the parameter list too, matching by dependency-name/type shape instead of a fixed name list.

All six fixes shipped with a permanent fixture under `test-fixtures/safe/`.

### Also
- Skill/MCP-server tool descriptions rewritten with explicit trigger phrasing ("is this skill safe?", "scan my MCP config") for better auto-suggestion in Claude/Cursor.
- `docs/RealWorldFindings.md` updated with the full litellm regression story.

## 0.9.0 — 2026-08-12

Support for the official OWASP Top 10 for LLM Applications 2026, plus five new Agent Skill detection rules.

### Added
- **Versioned OWASP 2026 reporting.** JSON includes `owaspVersion: "2026"`, terminal and CLI output use the official `LLMxx:2026` notation, Markdown/HTML name the framework version, and SARIF emits `owasp-llm-top10-2026/*` tags.
- **A conservative 2026 coverage statement.** `docs/OWASP2026.md` distinguishes implemented static signals, partial category coverage, and the runtime-only Misinformation boundary instead of presenting category mapping as exhaustive detection.
- **Taxonomy contract tests.** Tests lock all ten official names, every changed rule mapping, structured report metadata, SARIF tags, and the real built CLI output.
- **SKL006: Load-time command execution in agent skills.** Flags Claude Code's dynamic-context-injection syntax when it runs shell commands the instant a skill is read — before Claude ever sees the content or any tool-permission gate applies.
- **SKL007: Unscoped Bash grants.** Flags a bare `Bash` (or `Bash(*)`) in a skill's `allowed-tools` frontmatter, which pre-approves arbitrary shell execution for the whole turn with no confirmation prompt.
- **SKL008: Remote instruction fetch.** Flags skills whose real behavior is fetched from an external URL at runtime rather than checked into the reviewed bundle, so the payload can change after install with nothing left to re-review.
- **SKL009: Trust-elevated persistence.** Flags skills that write into a different trust-elevated context file (MEMORY.md, SOUL.md, AGENTS.md, CLAUDE.md), planting a backdoor that outlives the skill and can propagate to future sessions or collaborators.
- **SKL010: Unsafe deserialization tags.** Flags YAML/JSON tags that construct language-native objects (e.g. `!!python/object`) in skill-bundle metadata/config, which can execute code the moment an unsafe loader parses the file.
- Vulnerable and safe fixtures for SKL006–SKL010, plus catalog and explainer entries (`secureai-scan explain SKL006`–`SKL010`).

### Changed
- Remapped existing findings to the official 2026 ranking: Excessive Agency is LLM03, Supply Chain LLM04, Data and Model Poisoning LLM05, Unbounded Consumption LLM06, Misinformation LLM07, Hidden Context Exposure LLM08, Vector and Embedding Weaknesses LLM09, and Improper Output Handling LLM10. Detection behavior and evidence tiers are unchanged.

## 0.8.0 — 2026-08-05

Audit-driven hardening. Every item below came from reviewing the project the way an external evaluator would: claims checked against code, then the gaps closed.

### Added
- **Public trust controls for a single-maintainer project.** `GOVERNANCE.md` identifies release authority, review expectations, bus-factor limits, and succession behavior. `docs/ReleaseAssurance.md` documents release controls and non-guarantees, while `docs/benchmarks/v0.8.0.json` preserves machine-readable test, coverage, regression, and package evidence.
- **Independent security workflows.** CodeQL, a portable production dependency audit, and OpenSSF Scorecard now run alongside cross-platform CI on Node 22.12+ and 24. Every install job asserts the runtime before `npm ci`, preventing stale Node 20 jobs from falling through to native node-gyp compilation. The audit uses npm's advisory service instead of GitHub Dependency Review, so it works without enabling Dependency Graph. The project's own SecureAI-Scan workflow is blocking at high severity and uploads its report even on failure.
- **Search and evaluation metadata.** The README leads with a pinned install command and measured release evidence; GitHub Pages now exposes canonical metadata, structured application data, `robots.txt`, a sitemap, and `llms.txt` for MCP security, tool-poisoning, prompt-injection, and Agent Skill scanner discovery. `CITATION.cff` gives researchers and ecosystem audits a version-aware citation path.
- **Release integrity is now enforced locally.** `npm run release:check` runs the complete test suite, coverage thresholds, the reviewed real-repository regression gate, and an npm tarball dry run. `prepublishOnly` runs the same gate before a maintainer can publish manually; GitHub Actions never receives npm credentials or publishes packages.
- **The GitHub Action installs an exact scanner version by default.** Its shell inputs are passed through environment variables and Bash arrays instead of expression-expanded command strings, preventing workflow inputs from being reinterpreted as shell syntax.
- **Python is now AST-based.** Every `.py` file is parsed once with `tree-sitter` + `tree-sitter-python`; `src/scanner/python-ast.ts` indexes imports, calls, positional/keyword arguments, assignment targets (identifier, attribute, tuple/list), functions, decorators, scopes, dictionary fields, and strings for all Python rules. The interim lexical `code`/`logical` views and hand-written assignment parser were deleted — structural detection no longer depends on physical-line regex. This closes fake imports/calls in comments and docstrings, multiline calls and keyword arguments, class-handler attribute taint (`self.user_message = request.json[...]`), tuple assignment, and decorated async handlers. Tree-sitter error recovery keeps incomplete files scanable; target code is never imported or executed and no Python interpreter is required.
- **Python AST contract tests** cover node indexing, receiver/call identity, attribute and tuple taint, decorators, multiline keywords, malformed-file recovery, and fake syntax inside comments/docstrings. The existing safe/vulnerable corpus and real-repo regression gate validate the full rule surface.
- **A shared per-file AST index** (`getFileCalls` / `getFileFunctions` / `getCallsWithin` in `src/utils/ast.ts`), replacing the ~20 independent whole-file walks rules used to each perform. `getCallsWithin` slices the pre-order index by compiler span instead of walking a subtree.
- **DEP003 advisory data is now generated from OSV, not hand-typed.** `npm run sync-advisories` ([`scripts/sync-advisories.js`](scripts/sync-advisories.js)) pulls HIGH/CRITICAL advisories for an explicit LLM/MCP/RAG package watchlist and writes `src/scanner/advisories-generated.ts`. The check stays fully offline at scan time — the snapshot is bundled — but it is now refreshable instead of stale-by-construction. **2 → 164 advisories.** Advisories whose affected range can't be parsed into an exact comparison are dropped rather than shipped, since an always-on advisory is a false positive by construction.
- **`npm run regression` is a real gate.** It now writes a structured report per repo, fingerprints every `proven`/`likely` finding as `repo|rule|file` (line-free, so upstream churn isn't noise), and **exits non-zero on anything not in the reviewed baseline** at `test/regression-baseline.json`. `--update-baseline` accepts the current set. Previously this was "run it and read the output with judgment," which is not a gate.
- **Python LLM sinks are resolved through AST constructor bindings.** Variables (and `self.x` attributes) assigned from a known SDK constructor — `gateway = OpenAI()`, `bedrock = boto3.client("bedrock-runtime")` — make invocation-shaped calls on that receiver visible whatever it is named. This is the Python analogue of the TS scanner's import-resolved `resolveLlmSink`.

### Performance
**A `vercel/ai` scan (5,691 files) went from 217s to 62s — 3.5× — with identical findings.** Driven by a CPU profile rather than guesswork; details and the remaining known gaps are in [`docs/Performance.md`](docs/Performance.md), which previously claimed scan times were "in the multi-second range" and was simply wrong.

- The profile attributed **~95s of 150s to AST descendant iteration alone**, more than everything else combined — type resolution barely registered. Cause: every rule ran its own `getDescendantsOfKind`/`getDescendants` per file, so each file's AST was walked ~20 times per scan, and nested functions were re-walked once per enclosing scope on top of that. Rules now share one memoized pre-order walk per file.
- `resolveLlmSink` checks the generation-shaped method name and the file's imports *before* consulting the type checker. Since `resolveIdentifierModule` can only ever report a specifier the file itself imports, a file with no LLM SDK import cannot produce a resolved sink — the type checker never needed asking for the vast majority of files.
- `npm test` dropped from 42s to 16s as a side effect.
- `test/ast-index.test.js` asserts the index and the containment slice against ts-morph's own traversal (exact membership *and* document order). The optimization's failure mode is silence, so it is guarded by a correctness test rather than a flaky wall-clock one.

### Fixed
- **Python DEP003 compared the wrong version.** `readRequirementsCandidates` stripped the comparison operator, so `langchain>=0.1.0` was parsed as an exact pin of `0.1.0` and then tested against advisory ranges as though that were the installed version — producing `proven`-tier findings about a version the repo never declared. Only `==`/`===` are treated as exact pins now; every other specifier keeps its operator and resolves to "unknown".
- **Renaming a Python LLM client silently disabled every rule.** `LLM_CALL_PATTERNS` hardcoded the receiver names `client`, `llm`, `chain`, `model`, `co`, so an app using any other variable name got zero AI-rule coverage with no indication anything was skipped. The legacy name patterns are kept for cross-module clients but every rule relying on them (AI001, AI003, AI004, AI010) is now gated on the file actually importing an LLM SDK — closing the inverse false positive, where a `chain.invoke(...)` in an unrelated ETL file was reported as prompt injection.
- **`test-fixtures/`-style directories weren't recognized as non-production.** `NON_PRODUCTION_SEGMENT` matched suffixed conventions (`ecosystem-tests`) but not prefixed ones, so a real repo laid out with `test-fixtures/`, `example-app/`, or `demo-server/` got undemoted findings — this repo's own self-scan exited 1 with 38 high-severity findings from its own fixtures. Both affix positions are handled now, still per-segment so `attestation`/`protest` are untouched.
- **`isTestFile` in the Python scanner recognized fewer paths than the TypeScript one.** It now delegates to the shared `isTestFilePath` and keeps only the Python-specific additions (`test_*.py`, `*_test.py`, `conftest.py`).

### Changed
- **CVEs and malicious packages get different ambiguity handling in DEP003.** A documented-malicious package still fires when the version can't be resolved — installing a backdoor is unrecoverable. A CVE now fires at `proven` only when the declared version is an exact pin provably inside the affected range; unpinned-but-possibly-affected drops to `heuristic` (`--paranoid`). Applying the malicious-kind rule to a 162-entry CVE snapshot would have put a critical finding on every repo with `langchain>=0.1.0`.
- Multiple advisories on one package now group into a single finding instead of one per CVE.
- The repo's own [`.secureai-policy.json`](.secureai-policy.json) now skips `test-fixtures/` and `.regression-cache/`, so `secureai-scan scan .` on this repo is a real signal instead of a wall of intentionally-vulnerable fixture hits. It reports clean.
- README: dropped the unprovable "first scanner mapped to all three OWASP frameworks" claim, and corrected the advisory-list and regression-benchmark descriptions to match what the code actually does.

## 0.7.0 — 2026-08-01

### Added
- **SVG dataflow diagrams in HTML reports.** `--output report.html` now renders every finding's source→flow→sink trace as an inline node-link diagram instead of a flat text list, with a dashed arrow + "cross-file" label wherever a step crosses a file boundary.
- **Trace coverage extended to four more rules** — MCP003 (tool result elevated to system-role), AI005 (unsafe output handling), AI012 (unvalidated structured output), and VEC003 (user content ingested into a vector store) now carry a full `source → sink` (or `source → flow → sink`) trace, matching AI001's existing dataflow evidence.
- **AI001 now traces across function and file boundaries.** When a tainted parameter is passed into a locally-resolved helper function (same project, import-resolved, not a name guess), the scanner follows the call up to 2 hops and builds a multi-file trace through the real call graph, capped at `likely` evidence (never `proven`) and guarded against cycles (mutual recursion produces exactly one finding, not an infinite loop or duplicates).

### Fixed
- **AI012 could never fire.** `hasSchemaValidationNearby`'s pattern list included bare `.parse(`, which always matched the rule's own `JSON.parse(` detection target, making the rule permanently silent regardless of input. Fixed with a validator-specific pattern that excludes `JSON.parse` while still catching real schema calls (`mySchema.parse(...)`); locked in with a new vulnerable/safe fixture pair.

### Notes
- The interprocedural AI001 walker's main value is an accurate, honestly-capped cross-file trace and visualization — not new recall on its own. The rule's existing per-parameter taint fallback already flags the same callee sink locations in isolation (by design, since caller context can be internal); the walker's job is to prove and display the real path when one exists, not to catch cases the base rule was missing.

## 0.6.1 — 2026-08-01

### Fixed
- **DEP001 flagged every scoped npm package (`@types/node`, `@anthropic-ai/*`, `@vercel/*`, ...) as "not found in npm."** `isReasonablePackageName`'s sanity-check regex had no `/`, so any scoped name was rejected before the registry was ever queried, always resolving to a false "not found." Found by running the scanner against its own `package.json`. Fixed the regex to accept an optional `@scope/` prefix; added a permanent fixture in `test/dependency-guard.test.js`.

### Added
- Marketing/discoverability source assets (`mcp-attack-diagram.png`, `rag-poisoning-diagram.png`) for upcoming Dev.to articles on MCP tool poisoning and RAG data poisoning. The demo GIF and social preview card are staged but held back from this release pending compression/regeneration — see `MARKETING.md`.

## 0.6.0 — 2026-07-28

Evasion-resistant Agent Skill scanning. In July 2026, [*Cloak and Detonate*](https://arxiv.org/abs/2607.02357) (arXiv:2607.02357) showed that nine published skill scanners could be bypassed by >80% (structural obfuscation) and ≥90% (self-extracting packing) using transformations that preserve the payload exactly; separately, Gecko Security demonstrated an exfiltration payload hidden in a `*.test.ts` file that every public scanner skipped. SecureAI-Scan v0.5.0 was vulnerable to all of these. This release closes each published technique, and was additionally validated against two real-world corpora added to `scripts/regression-scan.js`: the canonical [anthropics/skills](https://github.com/anthropics/skills) repo (18 real skill bundles, zero findings — a pure precision check) and [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)'s own labeled eval corpus (20 skills under `evals/`, each with an `_expected.json` verdict and a directory literally named `malicious/` or `safe/`) — a rare case where a real-world repo doubles as a recall check, not just a precision one. Result: 6/6 in-scope malicious fixtures correctly flagged, zero findings on any fixture labeled safe.

### Added
- **Python AST migration spike** — established the feasibility of Tree-sitter and demonstrated the class-handler attribute-taint gap (`self.user_message = request.json[...]`). The spike was later superseded and removed when the production AST engine shipped; see the Unreleased section.
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
