# SecureAI-Scan for VS Code

Runs the [SecureAI-Scan](https://github.com/akanthed/SecureAI-Scan) CLI in the background and reports findings — prompt injection, MCP tool poisoning, RAG misconfig, Agent Skill poisoning — as Problems-panel diagnostics, right where you're editing.

Same offline, evidence-tiered scanner as the CLI and GitHub Action: nothing leaves your machine, and a default scan shows only `proven`/`likely` evidence — no heuristic noise unless you turn it on.

## What it does

- Scans the workspace whenever you save a `.ts`/`.tsx`/`.js`/`.jsx`/`.py` file, an `.mcp.json`/`claude_desktop_config.json`, or a `SKILL.md`.
- Findings show up as diagnostics in the Problems panel and as squiggles at the reported line, with the rule ID, evidence tier, and fix in the hover/related-information text.
- `SecureAI-Scan: Scan Workspace` and `SecureAI-Scan: Scan Current File's Project` in the Command Palette for an on-demand run.
- A status-bar item (`$(shield) SecureAI-Scan: N`) shows the last finding count; click it to re-scan.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `secureaiScan.scanOnSave` | `true` | Re-scan on every relevant file save. |
| `secureaiScan.paranoid` | `false` | Include heuristic-tier findings (matches the CLI's `--paranoid`). |
| `secureaiScan.minSeverity` | `low` | Only show findings at or above this severity. |
| `secureaiScan.cliPath` | *(bundled)* | Point at a different `secureai-scan` `dist/index.js` (e.g. a local build) instead of the version bundled with this extension. |

## Install (not yet on the Marketplace)

This extension isn't published yet — install it from a locally built `.vsix`:

```bash
cd vscode-extension
npm install
npm run package        # builds dist/ and produces secureai-scan.vsix
code --install-extension secureai-scan.vsix
```

## Development

```bash
cd vscode-extension
npm install
npm run build           # or: tsc -w
```

Then press F5 in VS Code (with this folder open) to launch an Extension Development Host with the extension loaded.

The extension never shells out to the network — it depends on the `secureai-scan` npm package directly (bundled into `node_modules` at install time) and invokes its built `dist/index.js`, the same code path as `npx secureai-scan`.
