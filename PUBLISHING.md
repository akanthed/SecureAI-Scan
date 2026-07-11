# Publishing SecureAI-Scan to npm

Everything you need to publish, update versions, and automate future releases.

---

## One-Time Setup

### 1. Create an npm Account

Go to [npmjs.com](https://www.npmjs.com) → Sign up.

Choose a username that matches or is close to your GitHub username (`akanthed`).

Enable 2FA immediately after signing up — npm will require it for publishing anyway.

### 2. Log In on Your Machine

```bash
npm login
```

You'll be prompted for username, password, and a one-time 2FA code.
After this, your credentials are stored and you won't need to log in again on this machine.

Verify it worked:
```bash
npm whoami
# should print: akanthed
```

### 3. Verify the Package Name is Available

```bash
npm view secureai-scan
```

If it returns package info — the name is taken (it's yours if you already published it).
If it returns an error "404 Not Found" — the name is available.

---

## Pre-Publish Checklist

Run through this every time before publishing:

```bash
# 1. Make sure you're on the main branch with no uncommitted changes
git status

# 2. Pull latest
git pull origin main

# 3. Build the TypeScript
npm run build

# 4. Verify the CLI works
node dist/index.js --version
node dist/index.js --help
node dist/index.js scan . --severity high

# 5. Run tests
npm test

# 6. Check what files will be published (should only be dist/, README.md, LICENSE)
npm pack --dry-run
```

Expected `npm pack --dry-run` output — you should see ONLY these:
```
dist/
dist/index.js
dist/scanner/...
README.md
LICENSE
package.json
```

If you see `.ts` source files, `.env` files, or test fixtures — add them to `.npmignore`.

### Create .npmignore (if it doesn't exist)

```bash
# .npmignore
src/
test/
test-fixtures/
examples/
*.cast
*.md
!README.md
.github/
MARKETING.md
PUBLISHING.md
THREAT_MODEL.md
tsconfig.json
.secureai-policy.json
.secureai-baseline.json
```

---

## Publishing — Step by Step

### First Publish

```bash
# Make sure version in package.json is correct (currently 0.2.0)
cat package.json | grep version

# Publish to npm (--access public is required for scoped packages,
# harmless for unscoped packages like this one)
npm publish --access public
```

You'll see output like:
```
npm notice Publishing to https://registry.npmjs.org/
+ secureai-scan@0.2.0
```

**Verify it's live:**
```bash
# Wait 30 seconds then:
npx --yes secureai-scan@latest --version
# Should print: 0.2.0
```

Also check: [npmjs.com/package/secureai-scan](https://www.npmjs.com/package/secureai-scan)

---

### Publishing Updates

Every time you make changes and want to release:

**Step 1: Bump the version**

Use npm's version command — it updates `package.json` AND creates a git tag automatically:

```bash
# For bug fixes (0.2.0 → 0.2.1)
npm version patch

# For new features that don't break anything (0.2.0 → 0.3.0)
npm version minor

# For breaking changes (0.2.0 → 1.0.0)
npm version major
```

**Step 2: Build**

```bash
npm run build
```

**Step 3: Publish**

```bash
npm publish
```

**Step 4: Push the version tag to GitHub**

```bash
git push origin main --follow-tags
```

This pushes both the commit and the version tag (e.g. `v0.2.1`) to GitHub.

---

## Version Numbering Guide

Follow semantic versioning (semver). Users depend on this to know if an update is safe.

| Change type | Example | Command |
|------------|---------|---------|
| Bug fix, no new features | Fixed false positive in AI001 | `npm version patch` |
| New rule added | Added MCP004 | `npm version minor` |
| New command added | Added `threat-model` command | `npm version minor` |
| Removed a rule or changed rule IDs | Renamed VEC001 to VEC100 | `npm version major` |
| Changed CLI flag names | `--only-ai` renamed | `npm version major` |

**Current planned releases:**
- `0.2.1` — any bug fixes from community feedback
- `0.3.0` — Python support or new rule category
- `1.0.0` — when the rule set is stable and well-tested

---

## Automated Publishing with GitHub Actions

Set this up once and every future release publishes automatically when you push a version tag.

### Step 1: Create an npm Access Token

1. Go to [npmjs.com](https://www.npmjs.com) → Your account → Access Tokens
2. Click "Generate New Token" → Choose "Automation" (works even with 2FA)
3. Copy the token — you'll only see it once

### Step 2: Add Token to GitHub Secrets

1. Go to your GitHub repo → Settings → Secrets and Variables → Actions
2. Click "New repository secret"
3. Name: `NPM_TOKEN`
4. Value: paste the token from Step 1
5. Click "Add secret"

### Step 3: Create the Publish Workflow

Create this file in your repo:

```yaml
# .github/workflows/publish.yml
name: Publish to npm

on:
  push:
    tags:
      - "v*"  # Triggers on any tag like v0.2.0, v1.0.0

jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-node@v4
        with:
          node-version: "22"
          registry-url: "https://registry.npmjs.org"

      - name: Install dependencies
        run: npm ci

      - name: Build
        run: npm run build

      - name: Run tests
        run: npm test

      - name: Publish to npm
        run: npm publish --access public
        env:
          NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}
```

**How to use it going forward:**

```bash
# Make your changes, commit them
git add .
git commit -m "feat: add Python support"

# Bump version (updates package.json + creates git tag)
npm version minor

# Push code + tag — GitHub Actions publishes automatically
git push origin main --follow-tags
```

GitHub Actions runs the tests, builds, and publishes. You never touch `npm publish` manually again.

---

## npm Page Optimisation

Your npm package page is at [npmjs.com/package/secureai-scan](https://www.npmjs.com/package/secureai-scan).
It pulls content directly from your repo. To make it look good:

### Keywords (in package.json — already set, verify these are there)

```json
"keywords": [
  "security", "ai", "llm", "scanner", "cli", "typescript",
  "prompt-injection", "appsec", "mcp", "rag", "vector-database",
  "devsecops", "owasp", "langchain", "openai"
]
```

Add `"mcp"`, `"rag"`, `"vector-database"`, `"devsecops"`, `"owasp"`, `"langchain"`, `"openai"` to the keywords array now — they drive npm search results.

### Description (in package.json)

Change from:
```
"Repo-native AI security scanning CLI for LLM-specific risks"
```

To:
```
"Find AI/LLM security vulnerabilities in your code — prompt injection, MCP tool poisoning, RAG data poisoning, agent trust violations. 19 rules. Local-first."
```

### README Shows on npm Page

The README.md you have is shown directly on the npm page. The badges, table of contents, and code examples all render. It's already in good shape.

---

## After Publishing — Announce It

**Immediately after `npm publish` succeeds:**

1. Update the README badge to show the real npm version:
   ```markdown
   [![npm version](https://img.shields.io/npm/v/secureai-scan)](https://www.npmjs.com/package/secureai-scan)
   ```
   This badge auto-updates — no changes needed.

2. Post on X/Twitter:
   ```
   SecureAI-Scan v0.2.0 is on npm.

   19 rules covering AI, MCP, and RAG security vulnerabilities.
   Runs locally. Free. Zero config.

   npx --yes secureai-scan@latest scan .

   What's new in 0.2.0: MCP rules (tool poisoning, dynamic server URLs),
   Vector/RAG rules (data poisoning, unbounded search, cross-tenant leakage),
   threat model generation, policy file enforcement.

   [GitHub link]
   ```

3. Post the Hacker News Show HN (from MARKETING.md)

---

## Troubleshooting

**"You do not have permission to publish"**
You're not logged in, or the package name is owned by someone else.
Run `npm whoami` — if it returns nothing, run `npm login` again.

**"Cannot publish over existing version"**
You already published this version number. Run `npm version patch` to bump and try again.

**"Package name too similar to existing package"**
npm may block names similar to popular packages. If this happens, consider:
`@akanthed/secureai-scan` (scoped package — free, just change the name in package.json)

**GitHub Actions publish fails with 401**
The NPM_TOKEN secret has expired or was deleted. Generate a new Automation token from npmjs.com and update the GitHub secret.

**Build succeeds locally but fails in Actions**
Check that your `package.json` `"engines"` field matches the Node version in the workflow (`"node": ">=22"`).

---

## Version History to Document

Keep a CHANGELOG.md for users who want to know what changed:

```markdown
# Changelog

## 0.2.0 — 2026-06-07
### Added
- 9 new security rules: AI010, AI011, AI012, MCP001, MCP002, MCP003, VEC001, VEC002, VEC003
- `secureai-scan init` command — first-time setup with policy file and CI workflow
- `secureai-scan threat-model` command — generates THREAT_MODEL.md
- `--only-mcp` and `--only-vec` scan filters
- `--min-confidence` flag — control false-positive sensitivity
- `--policy` flag — enforce .secureai-policy.json in CI
- Policy file exits with code 1 on `failOnSeverity` threshold breach

### Improved
- Confidence scoring now penalises test files, sanitized contexts, embedding-only calls
- All rules now include detailed `howToFix` guidance
- Terminal output shows confidence-hidden finding count

## 0.1.6 — 2026-04-28
- Initial rules: AI001–AI009, AI100
- Baseline diff mode
- HTML, Markdown, JSON reports
- Dependency scanning
- Prompt risk evaluator
```

Create `CHANGELOG.md` in the repo root with this content.
