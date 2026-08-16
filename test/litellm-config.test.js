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
