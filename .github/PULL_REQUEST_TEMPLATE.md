## What and why

<!-- What does this change, and why? Focus on the "why" — the diff already shows the "what". -->

## Detection logic changes (delete this section if not applicable)

- [ ] `npm run regression` was run and every `proven`/`likely` finding it printed was reviewed against its source line
- [ ] A new/updated rule has fixtures in both `test-fixtures/vulnerable/` and `test-fixtures/safe/`
- [ ] `src/scanner/catalog.ts` and `src/scanner/explainer.ts` both have an entry for any new rule ID
- [ ] `test/corpus.test.js`'s `EXPECTED_VULNERABLE` was updated for any new rule

## CLI changes (delete this section if not applicable)

- [ ] `test/cli.test.js` has a new or updated case exercising the built binary (`src/cli.ts` changes aren't covered by any other test file)

## Checklist

- [ ] `npm run build && npm test` passes
- [ ] Before/after behavior is described above, with a concrete example if the change affects scan output
