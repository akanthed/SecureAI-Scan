# FAQ

**Is this a replacement for Semgrep / Trivy / GitHub Advanced Security?**
No — see the [comparison table in the README](../README.md#how-it-compares). SecureAI-Scan is scoped to LLM/MCP/RAG risk specifically; it doesn't do general SQLi/XSS/path-traversal SAST or container/IaC scanning, and isn't trying to. Run it alongside a general SAST tool, not instead of one.

**MCP013/MCP014 are command-injection and path-traversal rules. Isn't that general SAST?**
No, because of the source. They only follow **MCP tool arguments**, values written by a model, which a prompt injection in anything the agent reads can choose. A form field from your own web app reaching `exec` is not reported; that is general SAST's job. Command injection through tool arguments is item MCP05 of the OWASP MCP Top 10 and accounts for most real MCP server CVEs, and a general SAST rule doesn't know that a tool handler's parameters are attacker-controlled. Both rules also report only an intent the code fails to keep (a fixed command the argument can break out of, a base directory it can walk out of). A tool built to run any command is `heuristic`, labeled as a by-design capability.

**Why doesn't rule X catch [specific real incident]?**
Two possible reasons. First, it might genuinely be a gap — file an issue with the [missed detection template](../.github/ISSUE_TEMPLATE/missed_detection.yml). Second, it might be an incident with no LLM/MCP/RAG-shaped payload (e.g. an AI-adjacent package with a generic backdoor unrelated to how it's used) — that class is handled by the offline `DEP003` advisory list (name + version, a documented fact), not a pattern rule, because a pattern broad enough to catch generic business-logic payloads would fire constantly on ordinary code. See [ThreatModel.md](ThreatModel.md) for the full scope boundary and the postmark-mcp case that established this precedent.

**I got a false positive. What do I do?**
File it with the [false positive template](../.github/ISSUE_TEMPLATE/false_positive.yml) — include the exact snippet and which rule fired. This project treats every false positive as a bug to root-cause-fix, not a "tune your config" problem; see the hard requirement in `CLAUDE.md`. In the meantime, suppress it inline:
```ts
// secureai-ignore AI001: reviewed, input sanitized via allowlist
```

**Why is a finding only `heuristic` and hidden by default? I want to see it.**
Run with `--paranoid`. Heuristic findings are real signal, just without a resolved sink or traced dataflow behind them — worth a look, not worth interrupting a default CI run over. See [DetectionEngine.md](DetectionEngine.md) for what separates the three evidence tiers.

**Does this send my code anywhere?**
No. Everything runs locally; nothing leaves your machine. The only network calls in the entire tool are opt-in: `--check-dependencies` (npm/PyPI registry lookups for typosquat detection), and the fetch step of `skill`/`mcp` and of `installed --deep` (a tarball download or a shallow git clone to scan; nothing fetched is ever executed). `installed` without `--deep` is fully offline, and it reads only the MCP server entries from each client config, never session state or tokens.

**Can I scan an MCP server or Agent Skill before installing it?**
Yes — that's what `secureai-scan skill <target>` and `secureai-scan mcp <target>` are for. They accept a GitHub `owner/repo` shorthand, a full git URL, a local path, or (for `mcp`) a bare npm package name. The target is fetched (npm: `npm pack` only, no `install`, no lifecycle scripts; git: `git clone --depth 1`), scanned, then deleted (`--keep` to inspect it instead). See the README's "Scan before you install" section.

**Why does the Python scanner seem weaker than the TS/JS engine?**
Both engines are AST-based. Python uses Tree-sitter for imports, calls, assignments, decorators, scopes, arguments, and strings; TypeScript uses ts-morph and has deeper symbol resolution and bounded interprocedural tracing. The remaining difference is semantic depth, not parsing correctness — see [Architecture.md](Architecture.md) and [ROADMAP.md](../ROADMAP.md).

**How do I add a new detection rule?**
[WritingRules.md](WritingRules.md) is the step-by-step checklist; [RuleDevelopment.md](RuleDevelopment.md) covers the day-to-day loop and how a rule PR gets reviewed.

**Does this work in CI?**
Yes — SARIF output (`--output report.sarif`) puts findings inline on PRs and in the GitHub Security tab. See the README's GitHub Action example, or run `secureai-scan init` to scaffold a workflow automatically.

**What Node/TypeScript/Python versions are supported?**
Node `>=22.12.0` (see `package.json` `engines`). TypeScript scanning works on any `.ts`/`.tsx`/`.js`/`.jsx` regardless of the target project's own TS version, since ts-morph parses independently. Python is parsed by Tree-sitter and does not require Python to be installed — SecureAI-Scan never executes your code.
