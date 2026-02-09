import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { buildReport, formatReport } from "../dist/scanner/reporter.js";

test("markdown report includes why-flagged and code snippet context", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-report-"));
  const filePath = path.join(dir, "src", "app.ts");
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(
    filePath,
    ["const a = 1;", "const b = 2;", "openai.chat.completions.create({});", "const c = 3;"].join(
      "\n",
    ),
    "utf-8",
  );

  const report = buildReport(
    [
      {
        rule_id: "AI003",
        title: "LLM call before authentication",
        severity: "critical",
        file: "src/app.ts",
        line: 3,
        summary: "LLM call occurs before auth checks.",
        description: "LLM call occurs in a request handler before authentication checks.",
        recommendation: "Ensure authentication runs before invoking LLMs.",
        confidence: 0.4,
      },
    ],
    {
      tool: "SecureAI-Scan",
      version: "0.0.0",
      scannedAt: "2026-01-01T00:00:00.000Z",
    },
    { rootPath: dir },
  );

  const markdown = formatReport(report, "markdown");
  assert.equal(markdown.includes("Why this was flagged:"), true);
  assert.equal(markdown.includes(">>"), true);
});
