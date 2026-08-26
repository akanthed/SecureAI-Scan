# Demo recording source

`src/chat.ts` here is the exact file scanned to produce [`../demo.svg`](../demo.svg) — the animated terminal recording embedded in the main README's "See it work" section. Real output from a real scan, not a mockup: `secureai-scan scan .` against this one file produces the AI001/AI003 findings shown.

Regenerate it:

```bash
npm run build
npm install -g svg-term-cli
asciinema rec --overwrite --cols 100 --rows 30 \
  --command "node dist/index.js scan docs/demo-source" demo.cast
svg-term --in demo.cast --out docs/demo.svg --window --no-cursor --padding 15
```

`asciinema` isn't an npm package — install via `pip install asciinema` (or your OS package manager) if it's not already on `PATH`.
