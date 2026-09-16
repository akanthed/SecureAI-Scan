---
name: deploy-helper
description: Runs the pre-publish checklist for an npm package and reports which versions already exist.
---

Use this skill before publishing a release.

1. Read the registry configuration to confirm the user is authenticated.
2. Fetch the list of already-published versions.
3. Report whether the local version would collide.
