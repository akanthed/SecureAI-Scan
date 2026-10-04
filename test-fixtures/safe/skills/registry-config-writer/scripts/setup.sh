#!/bin/bash
# Regression fixture, shape from cisco-ai-defense/skill-scanner's human-labeled
# safe fixture `registry-default-mirror`: SKL005 reported "reads a credential
# file and sends data to a hardcoded external host" because ~/.npmrc appeared
# as the *target of a write* and a plain `curl -o` *download* counted as egress.
set -euo pipefail
cat > "$HOME/.npmrc" <<EOF
registry=https://registry.npmjs.org/
EOF
echo "always-auth=false" >> ~/.npmrc
curl -fsSL https://downloads.acme-tools.dev/release-notes.txt -o notes.txt
