# Release Assurance

SecureAI-Scan is a single-maintainer open-source project. Trust comes from reproducible evidence and constrained release authority, not from a claim of independent certification.

## Controls applied to every release

`npm run release:check` performs four gates:

1. Builds the TypeScript project and runs the complete test suite.
2. Enforces minimum coverage of 80% statements, 80% lines, 80% functions, and 75% branches.
3. Scans the curated real-repository corpus and rejects any new default-tier fingerprint outside the reviewed baseline.
4. Inspects the npm tarball contents before publication.

`prepublishOnly` invokes the same release gate when the maintainer runs `npm publish`. Target repositories are parsed and read; their code is never imported or executed.

## Independent platform checks

Pull requests and `main` run on Linux, Windows, and macOS with Node 22.12+ and 24. Every install job asserts the runtime before `npm ci`, so stale Node 20 jobs fail clearly before native dependencies invoke node-gyp. GitHub also runs CodeQL, a production-only `npm audit`, OpenSSF Scorecard, Dependabot, and SecureAI-Scan against its own repository. High and critical self-scan findings block CI. The dependency audit does not require GitHub Dependency Graph.

These checks are independent implementations, not proof that the package is vulnerability-free.

## Release authority and credentials

GitHub Actions does not receive npm credentials and cannot publish the package. The maintainer authenticates directly with npm using account protections and publishes manually after the release gate passes. Release ownership and continuity are documented in [GOVERNANCE.md](../GOVERNANCE.md).

## Precision evidence

The fixture corpus tests both directions: expected vulnerable patterns must fire at `proven` or `likely`, and safe fixtures must produce no default-tier findings. The real-repository regression corpus checks behavior on code not written for this scanner.

Regression baselines are human-reviewed records, not an assertion that every baseline finding is exploitable. Framework source can structurally resemble unsafe application code; those known limits are retained and disclosed rather than hidden.

Versioned benchmark records live under [`docs/benchmarks/`](benchmarks/). They report the command, corpus, test totals, coverage, new findings, reviewed baseline findings, and known limitations.

## What this does not guarantee

- Static analysis cannot establish runtime safety.
- Passing a scan does not prove that an application or skill is secure.
- A default-tier finding can still require application-context review.
- The project has one maintainer and no contractual support SLA.
- The benchmark corpus is curated and cannot represent every framework or coding style.

Security teams should use SecureAI-Scan alongside general SAST, dependency, secret, runtime, and human review controls.