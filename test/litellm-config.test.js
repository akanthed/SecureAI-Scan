import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanLiteLlmConfigs } from "../dist/scanner/litellm-config-scanner.js";

test("litellm config scanner flags hardcoded secret, http endpoint, and missing guardrails", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-litellm-"));
  fs.writeFileSync(
    path.join(dir, "config.yaml"),
    [
      "model_list:",
      "  - model_name: gpt-4",
      "    litellm_params:",
      "      model: openai/gpt-4",
      "      api_key: sk-live-4f9a8b7c6d5e4f3a2b1c",
      "      api_base: http://internal-llm.example.com/v1",
      "general_settings:",
      "  master_key: sk-master-abcdef1234567890",
    ].join("\n"),
  );

  const findings = scanLiteLlmConfigs(dir);
  const ids = findings.map((f) => f.rule_id).sort();
  assert.deepEqual(ids, ["LLC001", "LLC001", "LLC002", "LLC003"]);
  assert.ok(findings.filter((f) => f.rule_id !== "LLC003").every((f) => f.evidence === "proven"));
  assert.equal(findings.find((f) => f.rule_id === "LLC003").evidence, "heuristic");
});

test("litellm config scanner accepts env references, https, and a populated guardrails section", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-litellm-safe-"));
  fs.writeFileSync(
    path.join(dir, "config.yaml"),
    [
      "model_list:",
      "  - model_name: gpt-4",
      "    litellm_params:",
      "      model: openai/gpt-4",
      "      api_key: os.environ/OPENAI_API_KEY",
      "      api_base: https://internal-llm.example.com/v1",
      "general_settings:",
      "  master_key: os.environ/LITELLM_MASTER_KEY",
      "guardrails:",
      "  - guardrail_name: pii-mask",
      "    litellm_params:",
      "      guardrail: presidio",
      "      mode: pre_call",
    ].join("\n"),
  );

  assert.deepEqual(scanLiteLlmConfigs(dir), []);
});

test("litellm config scanner ignores an unrelated YAML file with a coincidental model_list field", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-litellm-gate-"));
  fs.writeFileSync(
    path.join(dir, "config.yaml"),
    [
      "apiVersion: v1",
      "kind: ConfigMap",
      "model_list: not-an-array",
      "data:",
      "  api_key: hardcoded-but-irrelevant-here",
    ].join("\n"),
  );

  assert.deepEqual(scanLiteLlmConfigs(dir), []);
});

test("litellm config scanner ignores model_list entries without litellm_params", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-litellm-gate2-"));
  fs.writeFileSync(
    path.join(dir, "config.yaml"),
    ["model_list:", "  - model_name: gpt-4", "  - model_name: gpt-3.5"].join("\n"),
  );

  assert.deepEqual(scanLiteLlmConfigs(dir), []);
});

// Regression: found scanning BerriAI/litellm itself. A repo with many
// model_list entries repeats the key name "api_key" dozens of times; the
// finding must anchor to the line holding the actual literal secret, not
// the first line in the file containing the word "api_key".
test("litellm config scanner anchors LLC001 to the offending value's line, not the first key match in the file", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-litellm-lineattrib-"));
  fs.writeFileSync(
    path.join(dir, "config.yaml"),
    [
      "model_list:",
      "  - model_name: safe-one",
      "    litellm_params:",
      "      model: azure/gpt-4",
      "      api_key: os.environ/AZURE_API_KEY",
      "  - model_name: leaky-one",
      "    litellm_params:",
      "      model: openai/gpt-4",
      "      api_key: sk-live-4f9a8b7c6d5e4f3a2b1c",
      "guardrails:",
      "  - guardrail_name: pii-mask",
    ].join("\n"),
  );

  const findings = scanLiteLlmConfigs(dir);
  const llc001 = findings.filter((f) => f.rule_id === "LLC001");
  assert.equal(llc001.length, 1);
  assert.equal(llc001[0].line, 9, "must point at the literal-secret line, not the env-ref line above it");
});
