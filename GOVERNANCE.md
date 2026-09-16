# Governance

SecureAI-Scan is currently maintained by Akshay Kanthed (`@akanthed`). This document makes the authority and limitations of a single-maintainer project explicit.

## Decision authority

The maintainer is responsible for releases, npm ownership, repository settings, security-response coordination, rule evidence tiers, and regression-baseline changes. Material decisions should be explained in a pull request, issue, changelog entry, or architecture document so they remain reviewable after the decision.

No contributor, automation account, or AI tool has release authority. Automated contributions receive the same tests and review requirements as human contributions.

## Contribution review

Contributions are welcome under [CONTRIBUTING.md](CONTRIBUTING.md). Detection changes must include recall coverage, plausible safe patterns, and the real-repository regression gate required by the project. A reviewed baseline is not a suppression list: each added fingerprint must correspond to a finding read against its source.

The maintainer may ask external domain experts to review a rule or advisory without granting repository or npm access. Such review is credited only with the reviewer's consent.

## Release authority

Only the maintainer publishes the npm package. GitHub Actions never receives npm credentials and never publishes a release. The mandatory local release checks and manual publication procedure are documented in [PUBLISHING.md](PUBLISHING.md).

## Security reports

Vulnerabilities in the scanner itself follow [SECURITY.md](SECURITY.md). Detection gaps and false positives use the public issue templates because transparency about scanner coverage benefits users. Private reports are not converted into public issues until disclosure is safe.

## Continuity

This project currently has a bus factor of one. It does not claim an enterprise support SLA or guaranteed continuity.

If the maintainer plans an extended absence or stops maintaining the project, the preferred path is to appoint a contributor with a demonstrated record of technically sound, precision-preserving work. Repository and npm access are transferred separately and minimally. If no suitable successor exists, the repository will be archived with a clear notice rather than presented as actively maintained.

Organizations requiring contractual support, multiple release approvers, or guaranteed response times should treat SecureAI-Scan as a transparent supplementary control and apply their own vendor-risk process.

## Changes to governance

Governance changes are made through a public pull request and recorded in the changelog when they alter release authority, security reporting, or continuity expectations.