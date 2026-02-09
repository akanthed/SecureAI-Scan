import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanDependencyFilesForRisks } from "../dist/scanner/dependency-guard.js";

class FakeChecker {
  async exists(ecosystem, name) {
    if (ecosystem === "npm" && name === "hallucinated-pkg") {
      return false;
    }
    return true;
  }
}

test("dependency guard flags missing and suspicious dependency names", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-deps-"));

  fs.writeFileSync(
    path.join(dir, "package.json"),
    JSON.stringify(
      {
        name: "tmp",
        version: "1.0.0",
        dependencies: {
          opena1: "1.0.0",
          "hallucinated-pkg": "1.0.0",
        },
      },
      null,
      2,
    ),
  );

  fs.writeFileSync(path.join(dir, "requirements.txt"), "reqests==2.31.0\n");

  const findings = await scanDependencyFilesForRisks({
    rootPath: dir,
    checker: new FakeChecker(),
  });

  const ruleIds = findings.map((f) => f.rule_id);
  assert.equal(ruleIds.includes("LLM_DEP001"), true);
  assert.equal(ruleIds.includes("LLM_DEP002"), true);
});
