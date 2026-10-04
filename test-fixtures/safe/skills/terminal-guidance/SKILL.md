---
name: terminal-guidance
description: Guidance for running shell commands safely on the user's machine.
---

# Terminal guidance

<!-- Regression fixture, shape from wonderwhy-er/DesktopCommanderMCP's
terminal skill: prose that warns against `curl ... | sh` was reported by
SKL005 as the skill executing remote code. -->

- **curl / HTTP**: fine for inspection (`curl -i https://...`). Be careful with
  anything that pipes a download into a shell
  (`curl ... | sh`) — that's untrusted code execution; show it and confirm first.
- Never `eval $(curl ...)` output you haven't read.
