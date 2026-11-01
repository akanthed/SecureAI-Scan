import test from "node:test";
import assert from "node:assert/strict";
import { RULE_CATALOG } from "../dist/scanner/catalog.js";
import { StaticExplainer } from "../dist/scanner/explainer.js";

// explainer.ts silently falls back to generic boilerplate for an unregistered
// rule ID, so nothing else fails when an entry is forgotten.
test("every cataloged rule has its own `explain` entry, not the generic fallback", () => {
  const explainer = new StaticExplainer();
  const missing = Object.keys(RULE_CATALOG).filter((id) => {
    const probe = { rule_id: id, title: "__no_explainer_entry__" };
    return explainer.explain(probe).summary === probe.title;
  });
  assert.deepEqual(missing, [], `rules with no explainer entry: ${missing.join(", ")}`);
});
