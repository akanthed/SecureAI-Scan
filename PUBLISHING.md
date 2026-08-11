# Publishing SecureAI-Scan

Releases are published manually from a maintainer workstation. GitHub Actions builds and tests the project but never receives npm credentials and never publishes packages.

## npm authentication

Authenticate directly with npm before publishing:

```bash
npm login
npm whoami
```

Complete the password, browser, and 2FA prompts locally. Never add an npm password, token, or recovery code to GitHub secrets, repository files, terminal logs, or issue comments.

## Release gate

Run the release gate locally:

```bash
npm ci
npm run release:check
```

The gate must complete all of these:

1. Build and run every test.
2. Meet the configured coverage thresholds.
3. Pass the reviewed real-repository regression baseline.
4. Show only intended runtime files in `npm pack --dry-run`.

Review every new regression finding against its source. Fix false positives and add permanent safe fixtures. Update `test/regression-baseline.json` only for findings confirmed to be real.

## Create a release

1. Update `CHANGELOG.md` and set the release date.
2. Set the same version in `package.json` and `package-lock.json`.
3. Run `npm run release:check` from a clean worktree.
4. Commit and merge through the normal reviewed branch workflow.
5. Publish from the authenticated workstation. `prepublishOnly` automatically reruns the release gate:

```bash
npm publish --access public
```

6. After npm confirms the publication, create and push an annotated tag matching the package version exactly:

```bash
git tag -a v0.9.0 -m "secureai-scan v0.9.0"
git push origin v0.9.0
```

Pushing the tag creates no npm publication job. Keep the tag and manifest version identical so the GitHub release and npm artifact remain traceable.

## Verify the public artifact

After `npm publish` succeeds:

```bash
npm view secureai-scan@0.9.0 version dependencies dist.integrity
npx --yes secureai-scan@0.9.0 --version
npx --yes secureai-scan@0.9.0 scan .
```

Confirm that `tree-sitter` and `tree-sitter-python` are runtime dependencies. Create the matching GitHub release from the tag and include the relevant changelog section.

## Version policy

- Patch: false-positive fix or compatible bug fix.
- Minor: new rule, scanner surface, command, or material analysis improvement.
- Major: removed or renamed rule, incompatible CLI flag, report-schema break, or stable `1.0.0` contract.

Never use `--ignore-scripts` to bypass `prepublishOnly`. Repair the failing test, coverage threshold, regression result, or package contents instead.