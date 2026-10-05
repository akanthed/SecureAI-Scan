# CLI reference

## Commands

```bash
secureai-scan scan .                          # proven + likely findings
secureai-scan installed                       # audit this machine's MCP servers and skills
secureai-scan scan . --output report.sarif    # also: .json, .md, .html
secureai-scan explain MCP013                  # why it's risky, the exploit, the fix
secureai-scan bom . --output AI_BOM.md        # AI bill of materials
secureai-scan threat-model .                  # THREAT_MODEL.md with the OWASP coverage matrix
secureai-scan init                            # policy file + CI workflow
```

**Everyday**

| Flag | What it does |
|------|---------------|
| *(none)* | `proven` + `likely` findings — the default, no flags needed |
| `--paranoid` | also include `heuristic`-tier findings |
| `-s, --severity <level>` | only show findings at/above `low`\|`medium`\|`high`\|`critical` |
| `--output <file>` | write a full report — `.sarif` (GitHub code scanning), `.json`, `.md`, or `.html` |

**Scope which rules run**

| Flag | What it does |
|------|---------------|
| `-r, --rules <list>` | run only these rule IDs, e.g. `AI001,MCP007` |
| `--only-ai` / `--only-mcp` / `--only-vec` / `--only-skl` | run only one rule category |
| `--check-dependencies` | also check `package.json`/`requirements.txt` against the npm/PyPI registry for typos and hallucinated packages (`DEP001`/`DEP002`). Auto-enabled if you select those rules directly via `-r` — you never need to remember to pass both. Not needed for `DEP003` (known-malicious packages), which always runs offline |

**CI / workflow**

| Flag | What it does |
|------|---------------|
| `--fail-on <severity>` | exit `1` if findings at/above this severity exist |
| `--baseline <file>` | track only new/changed issues against a saved baseline |
| `--policy <file>` | load thresholds, skipped paths, and blocked rules from a `.secureai-policy.json` (auto-detected if present — `secureai-scan init` creates one) |

**Advanced**

| Flag | What it does |
|------|---------------|
| `--min-confidence <0-1>` | finer-grained than `--paranoid`: hide findings below an exact confidence score (`0.9` proven / `0.65` likely / `0.35` heuristic) |
| `--limit <n>` | max rule groups shown in the terminal (default `10`) — full detail always goes to `--output` |
| `--debug` | print every file scanned and which rules ran |

Suppress a reviewed finding in code:

```ts
// secureai-ignore AI001: reviewed, input sanitized via allowlist
```

Back to the [README](../README.md).
