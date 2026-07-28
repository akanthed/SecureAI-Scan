# Roadmap

Where this scanner is going, and why — kept separate from [`CHANGELOG.md`](CHANGELOG.md) (what shipped) and [`MARKETING.md`](MARKETING.md) (how to talk about it). This file is the plan; update it as decisions change rather than letting it drift out of sync with reality.

## Where we stand (2026-07-28)

**Shipped in v0.6.0:** evasion-resistant Agent Skill scanning (SKL004/SKL005, deobfuscation-aware SKL001–003), validated against two real-world corpora — [anthropics/skills](https://github.com/anthropics/skills) (18 bundles, 0 findings) and [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)'s labeled eval set (6/6 malicious fixtures correctly flagged, 0 false positives). The pre-install wedge (`secureai-scan skill <target>` / `secureai-scan mcp <target>`) — fetch and scan before you trust, no clone or config required, nothing fetched is ever executed.

**In progress:** a full triage pass of `vercel/ai` (a 5,511-file real monorepo) turned up five root-cause bugs, all fixed and pinned as permanent fixtures:

- `resolveLlmSink` treated *any* call resolved to an LLM SDK module as an LLM invocation, with no check on the method name — flagging type guards like `isToolUIPart` (exported by the `ai` package right alongside `generateText`) as model calls. This alone caused three of the five finding groups in the sample (AI001, AI003, AI010).
- `DANGEROUS_CALLEES` in AI005 includes `"query"` for SQL-injection-style sinks, but `"query"` is *also* a legitimate LLM/agent invocation verb (`claudeSdk.query(...)`) — the same bare method name meant opposite things in two different rules.
- `REQUEST_SOURCES` (duplicated across MCP002, MCP010, VEC003) included a bare `"params."` entry, matching *any* function parameter conventionally named `params` — not necessarily HTTP request data.

This is the exact validation loop the project is built around: real code found real bugs, each was fixed at the root and locked in with a fixture, not patched around. See `CHANGELOG.md` for the full list.

## The four gaps, and what closes them

### 1. Python is regex-based, not AST-based

The TS/JS rules resolve real imports and walk a real AST (`ts-morph`). The Python scanner (`python-scanner.ts`) matches patterns line-by-line with a small taint pass — `CLAUDE.md` documents this as the most false-positive-prone surface in the codebase, and it's the majority language for production LLM/agent code.

**Plan:** integrate `tree-sitter-python` (WASM, pure-npm, no external Python interpreter required — keeps `npx secureai-scan` working with zero Python installed). Port rules incrementally behind the existing regex path as a fallback, so the precision gate never regresses mid-migration. Start with AI001 (prompt injection) as the proof of concept, since it has the most-documented false-negative history (see memory: litellm calls, >10-line taint gaps).

**Status: spiked (2026-07-28), not integrated.** `spike/python-ast-poc/` — not part of the shipped package, `tree-sitter-python`/`web-tree-sitter` are `devDependencies` only. Findings:

- **Technically viable exactly as planned.** `web-tree-sitter` + `tree-sitter-python`'s own bundled `.wasm` grammar (not the 51MB `tree-sitter-wasms` multi-language bundle) parses real Python with zero native compilation — confirmed by testing on this machine. `tree-sitter-python`'s own npm entry point pulls in `node-gyp-build`/native bindings; that path was deliberately avoided.
- **Found and closed a real, concrete gap** in the current regex scanner during the spike itself: `collectRequestTaintedVars` in `python-scanner.ts` only recognizes bare-identifier assignment targets, so `self.user_message = request.json[...]` — a common shape in any class-based handler (Flask `MethodView`, FastAPI DI classes, agent/session state) — is invisible to it, confirmed empirically (0 findings, even at `--paranoid`, on a textbook prompt-injection case). The AST-based POC catches it with no special-casing, because an assignment target is either an `identifier` or an `attribute` node either way — the gap only existed because the regex approach had to enumerate LHS shapes by hand and missed one.
- **Recall parity confirmed** on the shape the regex scanner already handles (bare-identifier taint), and **no precision regression** on a safe case (plain function argument, no request source) — 1/1/0 findings across the three test cases, exactly as expected.
- **Effort estimate for a real migration, based on what the POC didn't cover:** the POC is single-function, single-pass, no cross-function propagation, no sanitizer detection (`hasSanitization` in the current scanner), no evidence tiering, and covers only AI001's core shape — not the ~10 other Python rules that share `python-scanner.ts`'s taint infrastructure (AI003, AI004, AI005, AI007, AI010, MCP007–009, DEP checks). A full port is a genuine multi-session rewrite of that shared infrastructure, not an incremental patch — closer to "rebuild the Python surface on a new foundation" than "swap one function's implementation."

**Recommendation:** proceed. The technical risk is retired — this was the open question, and it's now answered with working code, not a guess. The remaining cost is pure engineering time, and the AI001 case alone (a completely invisible textbook vulnerability) is enough to justify it independent of the strategic case in the rest of this document. Next step, when picked up: expand the POC to a second rule (AI005 or AI007, since they read the same shared taint set) to confirm the "shared infrastructure" assumption before committing to the full rebuild.

### 2. No cross-file taint tracking

Confirmed gap, not theoretical: `cisco-ai-defense/skill-scanner`'s `multi-file-exfiltration` eval fixture splits a payload across four files specifically to defeat same-file analysis, and it does.

**Plan:** deliberately *not* a general interprocedural taint engine — that's a research project and a false-positive generator. Instead, bundle-scoped import-graph taint: inside one skill bundle or one MCP server package (a small, closed unit), resolve imports and propagate capability facts across the handful of files in that unit. Bounded scope is the point.

**Status:** not started.

### 3. Static analysis has a ceiling

*Cloak and Detonate* (arXiv:2607.02357) is correct that runtime detonation beats static analysis for an adaptive adversary. Competing on that axis loses to funded competitors (Cisco AI Defense ships a behavioral engine today).

**Plan:** reposition rather than chase. Emit a machine-readable capability manifest per skill/MCP server bundle — "reads `~/.aws/credentials`, egresses to X, executes Y" — that a runtime sandbox, an allowlist, or a CI gate can consume. The data mostly already exists (`detectCapabilities` in `skill-bundle.ts`, the AI-BOM, trace steps); the gap is a stable, documented, portable output format for it. "Declared vs. actual capability" as an artifact is not something any named competitor currently ships.

**Status:** not started. Depends on capability-detection maturing past the skill-bundle-only scope it has today.

### 4. Single-maintainer scale

Cannot out-engineer Cisco/Snyk on headcount. Can out-trust them on process.

**Plan:** a documented external rule format so contributors can add rules without touching core; the DEP003 advisory list as a citable, standalone feed; the precision contract (evidence tiers, the safe/vulnerable fixture corpus, the real-repo regression requirement) as the enforced bar for any contribution, not just internal discipline.

**Status:** not started.

## Distribution (the actual growth plan)

**The wedge is pre-install, not post-commit.** Shipped: `secureai-scan skill <target>` / `secureai-scan mcp <target>`. Next: get this into the places the decision actually gets made —

- A Claude Code / MCP-server-side integration (the `mcp-server/index.js` this project already ships is the natural host — scan a skill from *inside* the agent, before it's trusted).
- A VS Code / Cursor extension.
- A `pre-commit` hook alongside the existing GitHub Action.

**Ecosystem audit.** Scan every public MCP server and published skill; publish results as a standing, dated report. This is how MCP-Scan built its following, it doubles as marketing, and it feeds the advisory list — the one asset that compounds and that a competitor can't shortcut without doing the same legwork. Today's `vercel/ai` triage is a miniature proof of this: a few hours of pointing the scanner at real code found five real, fixable bugs.

**Compliance packaging.** The OWASP LLM/ASI/MCP triple mapping and auto-generated `threat-model` coverage matrix already exist and are underused as a selling point — EU AI Act evidence generation is badly underserved by US-centric competitors. "Produces the artifact your auditor asks for" sells independently of rule-count comparisons.

## Honest competitive position

| | Edge | Gap |
|---|---|---|
| Cisco skill-scanner | zero-config npm install, no cloud dependency, precision discipline | multi-engine behavioral + LLM analysis, funded team |
| MCP-Scan (Invariant Labs) | broader scope (skills + RAG + code, not MCP-only), evidence tiers | mindshare, first-mover, 2k+ stars |
| Snyk agent-scan | open source, transparent rules, no seat pricing | enterprise distribution, existing customer base |

**Not worth attempting:** a runtime/behavioral engine, general-purpose SAST/secret-scanning (explicitly out of scope — see `CLAUDE.md`), competing on raw rule count. Each loses on resources against funded competitors.

**Positioning:** the scanner whose findings don't need triaging, that runs before you install anything, and that hands your auditor a document — not the scanner with the most rules.
