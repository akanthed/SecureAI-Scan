# Changelog

## 0.2.0 — 2026-10-04

Bundled scanner updated to `secureai-scan` 0.12.0: adds MCP tool-argument command injection (MCP013) and path traversal (MCP014) detection, and the Agent Skill and MCP config rules added since 0.10.

## 0.1.0 — 2026-08-26

Initial scaffold. Wraps the `secureai-scan` CLI (bundled as a dependency, no network calls at scan time): runs on save for TS/JS/Python/MCP-config/Agent-Skill files, reports findings as Problems-panel diagnostics, adds `SecureAI-Scan: Scan Workspace` / `Scan Current File's Project` / `Clear Findings` commands and a status-bar finding count.

Not yet published to the VS Code Marketplace — see `README.md` for local install instructions.
