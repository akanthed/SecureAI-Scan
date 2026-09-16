#!/usr/bin/env node
import { execSync } from "node:child_process";

const expectedByFile = {
  "vulnerable/prompt_injection.ts": ["AI001"],
  "vulnerable/pii_to_llm.ts": ["AI004"],
  "vulnerable/llm_before_auth.ts": ["AI003"],
  "vulnerable/hardcoded_key.ts": [],
  "safe/prompt_injection.ts": [],
  "safe/pii_to_llm.ts": [],
  "safe/llm_before_auth.ts": [],
  "safe/hardcoded_key.ts": [],
};

console.log("Running SecureAI-Scan against test-fixtures/...\n");
execSync("node dist/index.js scan test-fixtures/ --only-ai", { stdio: "inherit" });

console.log("\nExpected rule IDs per file:");
for (const [file, rules] of Object.entries(expectedByFile)) {
  console.log(`- ${file}: ${rules.length > 0 ? rules.join(", ") : "none"}`);
}
