# Rules

**48 rules**, mapped to the [OWASP Top 10 for LLM Applications (2026)](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/) and, where applicable, the OWASP Top 10 for Agentic Applications (ASI) and the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/). See the [versioned coverage and limits](OWASP2026.md).

| Rule | What it reports | OWASP |
|------|-----------------|-------|
| AI001 | User input flows into a system/developer prompt (traced, including across function and file boundaries) | LLM01 |
| AI002 | Prompt content or secrets written to logs (in files that use an LLM SDK) | LLM02 |
| AI003 | LLM call in a request handler with no visible auth check | LLM06 |
| AI004 | Whole user/session object serialized into a prompt | LLM02 |
| AI005 | LLM output reaches eval/exec/SQL/HTML sinks | LLM10 |
| AI006 | High-impact tools (delete, pay, deploy, ...) exposed to a model without an approval gate | LLM03 |
| AI007 | Retrieved RAG content interpolated into privileged prompts | LLM01 |
| AI008 | Secrets embedded in system prompt text | LLM08 |
| AI009 | Unbounded user input / missing token limits | LLM06 |
| AI010 | Fetched external content flows into prompts | LLM01 |
| AI011 | Agent output elevated to system role in downstream calls | LLM03 |
| AI012 | LLM output parsed without schema validation | LLM10 |
| AI013 | Schema-validated LLM output reused as trusted input without content checks | LLM01 |
| AI014 | Untrusted input drives an action gated only by a model confidence score | LLM03 |
| MCP001 | MCP tool metadata reaches the system prompt without validation | LLM01 |
| MCP002 | MCP server URL constructed from user input | LLM04 |
| MCP003 | MCP tool results elevated to system role | LLM10 |
| MCP004 | MCP server launched as an unpinned `npx -y`/`uvx` package | LLM04 |
| MCP005 | Secret inlined in a committed MCP config | LLM02 |
| MCP006 | MCP server over plaintext HTTP | LLM04 |
| MCP007 | Invisible/bidi Unicode in MCP tool names or descriptions | LLM01 · MCP03 |
| MCP008 | Agent-directed injection phrases in MCP tool descriptions | LLM01 · MCP03 |
| MCP009 | A tool description that steers calls to a different tool (shadowing) | LLM01 · MCP03 |
| MCP010 | MCP stdio server command/args constructed from user input | LLM04 · MCP05 |
| MCP011 | Externally fetched content returned as a tool result without validation | LLM01 |
| MCP012 | MCP server launched through a raw shell interpreter | LLM04 · MCP04 |
| MCP013 | Tool argument interpolated into a shell command (command injection), traced across files | LLM10 · MCP05 |
| MCP014 | Tool argument joined onto a base path without a containment check (path traversal) | LLM10 · MCP02 |
| SKL001 | Invisible/bidi Unicode anywhere in an Agent Skill bundle | LLM01 |
| SKL002 | Agent-directed injection phrasing in a skill (matched through obfuscation) | LLM01 |
| SKL003 | A skill steers when/how a different skill is used (shadowing) | LLM01 |
| SKL004 | Staged payload: opaque blob + instructions to decode and run it | LLM04 · MCP04 |
| SKL005 | Credential read + external egress in a bundle file, or remote code fetched and executed | LLM02 · MCP04 |
| SKL006 | Load-time command execution via dynamic-context-injection syntax | LLM04 · MCP05 |
| SKL007 | Unscoped `Bash` grant in a skill's `allowed-tools` | LLM03 |
| SKL008 | Skill fetches instructions from an external URL and tells the agent to follow them | LLM04 |
| SKL009 | Skill persists itself by writing into another context file (`CLAUDE.md`, `AGENTS.md`, ...) | LLM05 |
| SKL010 | Unsafe YAML/JSON deserialization tag in skill frontmatter or config | LLM04 |
| VEC001 | Vector search without a tenant/user filter | LLM09 |
| VEC002 | Unbounded or user-controlled search limit | LLM06 |
| VEC003 | User content ingested into a shared vector store | LLM05 |
| VEC004 | Ingestion without tenant/namespace tagging | LLM09 |
| DEP001 | Dependency name not found in the registry (opt-in `--check-dependencies`) | LLM04 |
| DEP002 | Dependency name one edit away from a popular package (opt-in) | LLM04 |
| DEP003 | Dependency with a documented malicious release or critical CVE, checked offline | LLM04 · MCP04 |
| LLC001 | Hardcoded secret in a LiteLLM proxy `config.yaml` | LLM02 |
| LLC002 | LiteLLM proxy `api_base` over plaintext HTTP | LLM04 |
| LLC003 | LiteLLM proxy config with no `guardrails:` section (`--paranoid` only) | LLM03 |

Back to the [README](../README.md).
