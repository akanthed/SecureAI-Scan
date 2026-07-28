# Python AST migration spike

Proof-of-concept only — **not part of the shipped package** (outside `src/`,
outside `tsconfig.json`'s `include`, outside `package.json`'s `files`).
`tree-sitter-python`/`web-tree-sitter` are `devDependencies`, installed only
for someone working in this repo, never for an `npm install secureai-scan`
consumer.

## What this proves

`ai001-poc.ts` ports enough of AI001 (prompt injection via user input) to
demonstrate that [`tree-sitter-python`](https://www.npmjs.com/package/tree-sitter-python)
via [`web-tree-sitter`](https://www.npmjs.com/package/web-tree-sitter) (pure
WASM — confirmed no native compilation required, unlike `tree-sitter-python`'s
own native-binding entry point) can replace the regex/line-based approach in
`src/scanner/python-scanner.ts`, and closes a real, concrete gap in it:
`collectRequestTaintedVars` only recognizes bare-identifier assignment
targets, so `self.user_message = request.json[...]` — a common shape in any
class-based handler (Flask `MethodView`, FastAPI DI classes, agent/session
state objects) — is completely invisible to the current scanner, even at
`--paranoid`. An AST has no such gap: an assignment target is an `identifier`
or an `attribute` node either way, both handled identically because both are
real syntax nodes, not a hand-written character class that only anticipated
one shape.

## Running it

```bash
cd spike/python-ast-poc
npm install web-tree-sitter tree-sitter-python --no-save  # if not already present at the repo root
npx tsc -p tsconfig.json
node -e "
import('./dist/ai001-poc.js').then(async ({ scanPythonSourcePoc }) => {
  const fs = await import('node:fs');
  const findings = await scanPythonSourcePoc(fs.readFileSync('your_test.py', 'utf-8'));
  console.log(findings);
});
"
```

## Result

Tested against three cases:

1. **Attribute-assignment taint** (`self.user_message = request.json[...]`, LLM call >30 lines later): current regex scanner — 0 findings, even at `--paranoid`. POC — 1 finding, correctly traced.
2. **Bare-identifier taint** (the shape the regex scanner already handles): POC — 1 finding, same recall.
3. **Safe case** (plain function argument, no request source): POC — 0 findings, no regression in precision.

## What this does NOT prove

This is intentionally far short of a real AI001 port: no cross-function propagation, no sanitizer detection, no evidence tiering, no handling of the other ~10 Python rules that share taint-tracking infrastructure. See `ROADMAP.md` at the repo root for the honest scope/effort assessment of the full migration.
