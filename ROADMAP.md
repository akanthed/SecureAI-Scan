# Roadmap

Where this scanner is going, and why — kept separate from [`CHANGELOG.md`](CHANGELOG.md) (what shipped) and [`MARKETING.md`](MARKETING.md) (how to talk about it). This file is the plan; update it as decisions change rather than letting it drift out of sync with reality.

## Where we stand (2026-08-05)

**Shipped in v0.6.0:** evasion-resistant Agent Skill scanning (SKL004/SKL005, deobfuscation-aware SKL001–003), validated against two real-world corpora — [anthropics/skills](https://github.com/anthropics/skills) (18 bundles, 0 findings) and [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)'s labeled eval set (6/6 malicious fixtures correctly flagged, 0 false positives). The pre-install wedge (`secureai-scan skill <target>` / `secureai-scan mcp <target>`) — fetch and scan before you trust, no clone or config required, nothing fetched is ever executed.

**In progress:** a full triage pass of `vercel/ai` (a 5,511-file real monorepo) turned up five root-cause bugs, all fixed and pinned as permanent fixtures:

- `resolveLlmSink` treated *any* call resolved to an LLM SDK module as an LLM invocation, with no check on the method name — flagging type guards like `isToolUIPart` (exported by the `ai` package right alongside `generateText`) as model calls. This alone caused three of the five finding groups in the sample (AI001, AI003, AI010).
- `DANGEROUS_CALLEES` in AI005 includes `"query"` for SQL-injection-style sinks, but `"query"` is *also* a legitimate LLM/agent invocation verb (`claudeSdk.query(...)`) — the same bare method name meant opposite things in two different rules.
- `REQUEST_SOURCES` (duplicated across MCP002, MCP010, VEC003) included a bare `"params."` entry, matching *any* function parameter conventionally named `params` — not necessarily HTTP request data.

This is the exact validation loop the project is built around: real code found real bugs, each was fixed at the root and locked in with a fixture, not patched around. See `CHANGELOG.md` for the full list.

## The four gaps, and what closes them

### 1. Python AST foundation — shipped

**Status: complete (2026-08-05).** Python source is parsed synchronously with `tree-sitter` + `tree-sitter-python` in `src/scanner/python-ast.ts`. Imports, calls, arguments, keyword arguments, assignments (identifier, attribute, tuple/list unpacking), decorators, functions, scopes, dictionary fields, and string/docstring nodes all come from the syntax tree. The old lexical `code`/`logical` views and hand-written assignment parser were deleted; no production rule infers Python structure from physical lines.

The parser is a runtime dependency with prebuilt binaries for macOS/Linux/Windows on x64 and ARM64; no Python interpreter and no execution of target code is required. Tree-sitter error recovery keeps malformed files scanable instead of aborting the repository.

This closes the concrete class-handler gap that motivated the migration (`self.user_message = request.json[...]`), fake imports/calls inside comments and docstrings, multiline calls and keyword arguments, tuple assignment, and decorated async handlers. Direct AST contracts in `test/python-ast.test.js`, the vulnerable/safe corpus, and the real-repo regression gate protect both recall and precision.

**Remaining work:** bounded cross-function and cross-file propagation. The AST establishes correct syntax and scope; it does not automatically make arbitrary interprocedural taint sound. That is tracked below as a separate problem rather than being misrepresented as unfinished parsing.

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
