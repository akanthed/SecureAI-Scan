# Writing a Rule

Practical, step-by-step. Read [DetectionEngine.md](DetectionEngine.md) first for *why* these steps exist — this doc is the checklist.

## 1. Create the rule file

`src/scanner/rules/<name>.ts`, exporting a `Rule`:

```ts
export const myRule: Rule = {
  id: "AI013",
  title: "Short human-readable title",
  severity: "high", // low | medium | high | critical
  run(context) {
    const findings: Finding[] = [];
    // walk context.sourceFiles, use resolveLlmSink / getPromptParts from
    // llm-rule-utils.ts for anything touching an LLM call
    return findings;
  },
};
```

Reuse, don't reimplement:
- `resolveLlmSink(callExpr)` — is this call actually an LLM SDK call? Never name-match a callee.
- `getPromptParts(callExpr)` — extract prompt message parts with role (system/user/assistant).
- `isTestFilePath(filePath)` + `demoteEvidence(tier)` from `confidence.ts` — call both for any rule touching request/user-controlled data, unless your rule is deliberately in the SKL005 category (see [DetectionEngine.md](DetectionEngine.md)'s note on why that one rule doesn't demote).

## 2. Register it

Add to the `RULES` array in `src/scanner/rules/index.ts` (or `CONFIG_RULE_IDS`/`SKILL_RULE_IDS`/`DEPENDENCY_RULE_IDS` for the non-AST scanners). This array is also the source of truth for `AVAILABLE_RULE_IDS` — a rule not in it can't be selected via `-r`.

## 3. Add a catalog entry — two places, both easy to forget

- `src/scanner/catalog.ts`: title, OWASP LLM Top 10 mapping (required), ASI/MCP Top 10 mapping (if defensible), EU AI Act article (if relevant), impact, short fix. This feeds the `threat-model` coverage matrix automatically — no separate wiring.
- `src/scanner/explainer.ts`'s `DEFAULT_EXPLANATIONS`: why/exploit/fix content for `secureai-scan explain <RULE_ID>`. **This one fails silently** — an unregistered rule ID just falls back to generic boilerplate, nothing errors. Grep `explainer.ts` for an existing rule ID to see the expected shape before writing yours.

## 4. Pick an evidence tier deliberately

Ask: what would make this `proven`? What's the weakest defensible claim that's still `likely`? Is there any version of this finding that's just a pattern match with no resolved sink — and if so, that's `heuristic`, hidden by default.

Do not default to `likely` because it "feels about right." Trace back to an actual sink resolution or dataflow, or downgrade to `heuristic`.

## 5. Add fixtures — both directories, every time

- `test-fixtures/vulnerable/` — a minimal repro that must fire your rule at `proven` or `likely`.
- `test-fixtures/safe/` — if there's *any* plausible shape that looks similar but shouldn't fire (there almost always is), add it here. This is what stops your rule from becoming the next false-positive class in `CHANGELOG.md`.

Extend `EXPECTED_VULNERABLE` in `test/corpus.test.js` to assert your vulnerable fixture actually fires.

Every shipped rule has this coverage as of the current corpus (`test/corpus.test.js`'s `EXPECTED_VULNERABLE` list) — treat any gap you find as a bug to fix, not a pattern to copy.

## 6. Build, test, regression-scan

```bash
npm run build && npm test
npm run regression        # or: npm run regression -- <one-repo-name> for a faster loop
```

Read every `proven`/`likely` finding the regression scan prints against its source line in the real repo. A real issue: leave it. Not a real issue: it's a bug in your rule — fix the root cause, then add the offending pattern as a new `test-fixtures/safe/` fixture so `npm test` locks the fix in permanently. This is not optional for any change touching detection logic — see the "Hard requirements" section of `CLAUDE.md`.

## Common mistakes (all have caused real, shipped false positives)

1. Name-matching a callee instead of resolving it through imports.
2. Reimplementing prompt-part extraction instead of calling `getPromptParts`.
3. A bare substring/keyword match reaching `proven` or `likely` with no shape requirement.
4. Skipping `isTestFilePath` demotion on a rule that touches request-controlled data.
5. Forgetting the `safe/` fixture because the `vulnerable/` one passed and that felt like "done."
