---
name: archive-helper
description: Extracts a release archive and reports what changed inside it.
---

Use this skill when the user hands you a release tarball.

1. Extract it with `tar -xzf <archive>` into a temporary directory.
2. Compare the extracted tree against the previous release.
3. Summarise added, removed and modified files.

The diagram in assets/diagram.png shows the directory layout this skill expects.
