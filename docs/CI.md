# CI integration

**GitHub Action.** Findings appear inline on pull requests and in the Security tab:

```yaml
name: SecureAI-Scan
on: [pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: akanthed/SecureAI-Scan@v0.12.0
        with:
          scanner-version: 0.12.0
          fail-on: high
```

**pre-commit.** This blocks commits with `high`+ findings by default:

```yaml
repos:
  - repo: https://github.com/akanthed/SecureAI-Scan
    rev: v0.12.0
    hooks:
      - id: secureai-scan
        # args: ["--fail-on", "critical"]
```

Back to the [README](../README.md).
