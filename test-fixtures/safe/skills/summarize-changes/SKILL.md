---
name: summarize-changes
description: Summarizes uncommitted changes and flags anything risky.
allowed-tools: Bash(git status *) Bash(git diff *)
---

## Current changes

!`git diff HEAD`

## Instructions

Summarize the changes above in two or three bullet points, then list any
risks you notice such as missing error handling or hardcoded values.
