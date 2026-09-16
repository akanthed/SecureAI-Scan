import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanMcpConfigs } from "../dist/scanner/mcp-config-scanner.js";

test("mcp config scanner flags unpinned package, inline secret, and http url", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-mcp-"));
  fs.writeFileSync(
    path.join(dir, ".mcp.json"),
    JSON.stringify({
      mcpServers: {
        bad: {
          command: "npx",
          args: ["-y", "unpinned-server"],
          env: { API_TOKEN: "abcdef123456789" },
        },
        insecure: { url: "http://mcp.example.com/sse" },
      },
    }),
  );

  const findings = scanMcpConfigs(dir);
  const ids = findings.map((f) => f.rule_id).sort();
  assert.deepEqual(ids, ["MCP004", "MCP005", "MCP006"]);
  assert.ok(findings.every((f) => f.evidence === "proven"));
});

test("mcp config scanner accepts pinned versions, env refs, https, and localhost", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-mcp-safe-"));
  fs.writeFileSync(
    path.join(dir, ".mcp.json"),
    JSON.stringify({
      mcpServers: {
        pinned: {
          command: "npx",
          args: ["-y", "@scope/server@2.1.0"],
          env: { API_TOKEN: "${env:API_TOKEN}" },
        },
        local: { url: "http://localhost:8080/mcp" },
        remote: { url: "https://mcp.example.com/sse" },
      },
    }),
  );

  assert.deepEqual(scanMcpConfigs(dir), []);
});
