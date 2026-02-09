import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanRepositoryDetailed } from "../dist/scanner/scan.js";

test("ignore annotation suppresses next matching finding and records reason", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-ignore-"));
  const filePath = path.join(dir, "route.ts");
  fs.writeFileSync(
    filePath,
    `
      export const handler = async (req: any, res: any) => {
        // secureai-ignore AI003: reviewed in gateway auth
        const result = await openai.chat.completions.create({ messages: [{ role: "user", content: req.body.q }] });
        return res.json(result);
      };
    `,
    "utf-8",
  );

  const result = scanRepositoryDetailed(dir, { rules: ["AI003"] });
  assert.equal(result.findings.length, 0);
  assert.equal(result.ignoredFindings.length, 1);
  assert.equal(result.ignoredFindings[0].reason.includes("reviewed in gateway auth"), true);
});
