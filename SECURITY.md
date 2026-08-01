# Security Policy

Thanks for taking a look. We take security issues seriously, even in an early-stage project — doubly so given what this tool is.

## Supported versions

Only the latest published npm version is supported. There is no LTS branch at this stage of the project; upgrade to `secureai-scan@latest` before reporting an issue if you're on an older version.

## What counts as a security vulnerability here

This policy is for vulnerabilities **in the scanner itself** — for example:
- A path in `src/scanner/fetch-target.ts` (the `skill`/`mcp` commands' fetch step) that could execute code from an untrusted target instead of only inspecting it
- A path traversal, injection, or arbitrary-code-execution issue in the CLI or MCP server (`mcp-server/index.js`)
- Any way a malicious *scanned* repository could cause the scanner itself to execute attacker-controlled code (the scanner reads and parses files; it should never run them)

**A detection gap — a real vulnerability in someone else's code that SecureAI-Scan fails to flag — is not a security vulnerability in this project.** Please report those instead via the [missed detection issue template](https://github.com/akanthed/SecureAI-Scan/issues/new?template=missed_detection.yml) or the [false positive template](https://github.com/akanthed/SecureAI-Scan/issues/new?template=false_positive.yml) if it's a wrong-direction miss. These are public by design — bugs in detection logic don't need private disclosure, and being public helps other users understand current coverage limits.

## Reporting a Vulnerability

If you find a security issue in the scanner itself:
- Please do not open a public GitHub issue.
- Email `akshay.kanthed007@gmail.com` with:
  - A clear description of the issue
  - Steps to reproduce
  - Impact assessment (best effort)

We aim to acknowledge reports within a few days and will keep you updated as a fix is investigated. This is a small, early-stage project without a formal SLA — if you haven't heard back within a week, it's fine to follow up.

## Scope

This policy applies to the SecureAI-Scan CLI, the MCP server (`mcp-server/`), and related code in this repository. It does not cover the security of third-party MCP servers or Agent Skills that SecureAI-Scan happens to scan — flagging risk in those is the product's job, not a vulnerability in it.
