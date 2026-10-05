# How it compares

| | SecureAI-Scan | Semgrep (OSS rules) | Trivy | GitHub Advanced Security |
|---|---|---|---|---|
| Prompt injection, source→sink traced | ✅ import-resolved dataflow | ⚠️ pattern rules | ❌ | ⚠️ CodeQL can, no AI-specific ruleset |
| MCP server command injection / path traversal | ✅ tool-argument taint across files | ⚠️ generic exec rules, no notion of tool arguments | ❌ | ⚠️ generic queries |
| MCP tool poisoning / config risk | ✅ | ❌ | ❌ | ❌ |
| Agent Skill poisoning | ✅ bundle-aware, evasion-resistant | ❌ | ❌ | ❌ |
| RAG / vector-store access control | ✅ | ❌ | ❌ | ❌ |
| Known-malicious AI packages | ✅ offline, version-aware | ❌ | ⚠️ general CVE feed | ⚠️ Dependabot |
| General SAST (SQLi, XSS, ...) | ❌ out of scope | ✅ | ❌ | ✅ |
| Evidence tiers | ✅ | ❌ | ❌ | ⚠️ |
| SARIF / offline / no account | ✅ / ✅ / ✅ | ✅ / ✅ / ✅ | ✅ / ✅ / ✅ | native / ❌ / ❌ |

If you already run Semgrep or GHAS, keep them, and add this for the surface they don't model.

Back to the [README](../README.md).
