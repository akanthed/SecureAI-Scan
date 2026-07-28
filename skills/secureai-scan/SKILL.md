---
name: secureai-scan
description: Scans a repository for LLM, MCP, Agent Skill, and RAG security vulnerabilities using the secureai-scan CLI, and explains any findings with a concrete fix.
---

# SecureAI-Scan

Use this skill when the user asks for a security review of code that talks to an LLM, an MCP server, a vector store, or ships Agent Skills — or when they're about to install an MCP server or a Claude Skill from somewhere untrusted and want to check it first.

## Running a scan

```bash
npx --yes secureai-scan@latest scan .
```

Runs entirely offline, needs no configuration, and reports `proven`/`likely` findings by default (add `--paranoid` to also see lower-confidence heuristic findings). Read the terminal output directly — each finding includes the file, line, a plain-language description of the risk, and a concrete fix.

For a report to attach to a PR or share with a team, add `--output report.md` (or `.html`, `.json`, `.sarif` for GitHub code scanning).

## Explaining a finding

```bash
npx --yes secureai-scan@latest explain <RULE_ID>
```

Prints the exploit scenario and a before/after code fix for that specific rule.

## Reviewing an MCP server or Agent Skill before installing it

If the user is about to install an MCP server or a Claude Skill from GitHub, npm, or a link someone sent them, scan it *before* cloning or installing anything — `skill`/`mcp` fetch the target themselves and never execute anything they fetch (npm packages via `npm pack`, tarball only; git targets via `git clone --depth 1`):

```bash
npx --yes secureai-scan@latest skill <owner/repo-or-url-or-local-path>   # Agent Skill
npx --yes secureai-scan@latest mcp <npm-package-or-url-or-local-path>    # MCP server
```

If the target is already cloned locally, `scan <path>` works the same way and covers the whole repo, not just the skill/MCP-specific rules.

This checks for invisible/bidirectional Unicode hidden in tool or skill descriptions, agent-directed injection phrasing, cross-tool/cross-skill shadowing, unpinned package launches, known-malicious packages, and — for skills specifically — evasion techniques like homoglyph/zero-width obfuscation and payloads staged in `.git/` or a `*.test.ts` file. These are the patterns behind real incidents like the postmark-mcp backdoor, the WhatsApp MCP rug-pull, and the SkillCloak scanner-evasion research (arXiv:2607.02357).

## Interpreting results

- `critical`/`high` findings at `proven` or `likely` evidence are worth fixing before merging.
- `heuristic`-tier findings only appear with `--paranoid` — worth a look, not a hard blocker.
- Every finding includes a `recommendation` — apply it directly; it's written for the specific pattern that fired, not generic advice.

## What this skill does not do

It does not replace human security review, does not modify code (it only reports), and is not a general-purpose SAST or secrets scanner — its scope is LLM, MCP, RAG, and Agent Skill risks specifically. A finding outside that scope won't come from this tool.
