import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { scanRepositoryDetailed } from "../dist/scanner/scan.js";
import { scanPythonFiles } from "../dist/scanner/python-scanner.js";
import { createScanProject } from "../dist/scanner/project.js";
import { generateBom } from "../dist/scanner/bom.js";
import { catalogFor } from "../dist/scanner/catalog.js";
import { isTestFilePath } from "../dist/scanner/confidence.js";

/**
 * Locks in the false-positive and crash-safety fixes made in this session.
 * Each test reproduces the exact shape of code that used to misfire (or
 * crash), so a future regex/heuristic tweak that reintroduces the bug fails
 * loudly here instead of shipping silently.
 */

function tempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

// ── Windows glob exclusion (project.ts) ─────────────────────────────────────

test("createScanProject excludes node_modules and skipPaths regardless of platform", () => {
  const dir = tempDir("secureai-glob-");
  fs.mkdirSync(path.join(dir, "node_modules", "some-pkg"), { recursive: true });
  fs.writeFileSync(path.join(dir, "node_modules", "some-pkg", "index.js"), "eval(x);");
  fs.mkdirSync(path.join(dir, "vendor"), { recursive: true });
  fs.writeFileSync(path.join(dir, "vendor", "skip-me.ts"), "eval(x);");
  fs.writeFileSync(path.join(dir, "app.ts"), "export const x = 1;");

  const project = createScanProject(dir, ["vendor"]);
  const files = project.getSourceFiles().map((f) => f.getFilePath().replace(/\\/g, "/"));

  assert.equal(files.some((f) => f.includes("/node_modules/")), false);
  assert.equal(files.some((f) => f.includes("/vendor/")), false);
  assert.equal(files.some((f) => f.endsWith("/app.ts")), true);
});

// ── Python AI005/AI002 gating (python-scanner.ts) ───────────────────────────

test("AI005 does not fire on ordinary shell-outs with no LLM SDK in the file", () => {
  const dir = tempDir("secureai-py-audio-");
  fs.writeFileSync(
    path.join(dir, "audio.py"),
    [
      "import subprocess",
      "",
      "def decode(path):",
      "    result = subprocess.run(",
      '        ["ffmpeg", "-i", path, "-f", "f32le", "pipe:1"],',
      "        stdout=subprocess.PIPE,",
      "    )",
      "    return result.stdout",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  assert.equal(findings.some((f) => f.rule_id === "AI005"), false);
});

test("AI005 fires at critical/likely when LLM output has a confirmed dataflow link to a sink", () => {
  const dir = tempDir("secureai-py-llm-direct-");
  fs.writeFileSync(
    path.join(dir, "agent.py"),
    [
      "import openai",
      "import subprocess",
      "",
      "def run_agent(user_prompt):",
      "    completion = openai.chat.completions.create(",
      '        model="gpt-4",',
      '        messages=[{"role": "user", "content": user_prompt}],',
      "    )",
      "    result = subprocess.run(completion, shell=True)",
      "    return result",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  const finding = findings.find((f) => f.rule_id === "AI005");
  assert.ok(finding, "expected AI005 to fire");
  assert.equal(finding.severity, "critical");
  assert.equal(finding.evidence, "likely");
});

test("AI005 downgrades to heuristic/high when only a name match backs an indirect derivation", () => {
  const dir = tempDir("secureai-py-llm-indirect-");
  fs.writeFileSync(
    path.join(dir, "agent.py"),
    [
      "import openai",
      "import subprocess",
      "",
      "def run_agent(user_prompt):",
      "    completion = openai.chat.completions.create(",
      '        model="gpt-4",',
      '        messages=[{"role": "user", "content": user_prompt}],',
      "    )",
      "    output = completion.choices[0].message.content",
      "    result = subprocess.run(output, shell=True)",
      "    return result",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  const finding = findings.find((f) => f.rule_id === "AI005");
  assert.ok(finding, "expected AI005 to fire");
  assert.equal(finding.severity, "high");
  assert.equal(finding.evidence, "heuristic");
});

test("AI002 does not fire on logged fields when the file imports no LLM SDK", () => {
  const dir = tempDir("secureai-py-music-");
  fs.writeFileSync(
    path.join(dir, "test_music_gen.py"),
    [
      "import logging",
      "",
      "def generate(prompt):",
      '    logging.info(f"Prompt: {prompt}")',
      "    return synthesize(prompt)",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  assert.equal(findings.some((f) => f.rule_id === "AI002"), false);
});

// ── Python false-negative fixes (litellm coverage + AI001 taint window) ────

test("AI001/AI003/AI005 fire on a litellm app (previously undetected entirely)", () => {
  const dir = tempDir("secureai-py-litellm-");
  fs.writeFileSync(
    path.join(dir, "app.py"),
    [
      "import litellm",
      "from flask import Flask, request",
      "",
      "app = Flask(__name__)",
      "",
      '@app.route("/chat", methods=["POST"])',
      "def chat():",
      '    user_input = request.json["message"]',
      '    system_prompt = "You are a helpful assistant. " + user_input',
      "",
      "    response = litellm.completion(",
      '        model="gpt-4",',
      "        messages=[",
      '            {"role": "system", "content": system_prompt},',
      '            {"role": "user", "content": user_input},',
      "        ],",
      "    )",
      "",
      '    reply = response["choices"][0]["message"]["content"]',
      "    exec(reply)",
      "    return reply",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  const ruleIds = findings.map((f) => f.rule_id);
  assert.ok(ruleIds.includes("AI001"), "expected AI001 (prompt injection) to fire on litellm.completion");
  assert.ok(ruleIds.includes("AI003"), "expected AI003 (unauthenticated LLM call) to fire on litellm.completion");
  assert.ok(ruleIds.includes("AI005"), "expected AI005 (unsafe output handling) to fire on litellm.completion");
});

test("AI001 finds prompt injection when the LLM call is far from the tainted request read", () => {
  const dir = tempDir("secureai-py-ai001-gap-");
  fs.writeFileSync(
    path.join(dir, "app.py"),
    [
      "import openai",
      "from fastapi import FastAPI, Request",
      "",
      "app = FastAPI()",
      "",
      '@app.post("/chat")',
      "async def chat(request: Request):",
      "    body = await request.json()",
      '    user_input = body["message"]',
      "",
      "    request_id = generate_request_id()",
      "    log_incoming_request(request_id, user_input)",
      "",
      "    if is_rate_limited(request_id):",
      '        return {"error": "rate limited"}',
      "",
      "    conversation = load_conversation_history(request_id)",
      "    context_docs = retrieve_relevant_docs(user_input)",
      "",
      "    system_prompt = build_system_prompt(context_docs)",
      '    full_prompt = system_prompt + "\\n\\nUser said: " + user_input',
      "",
      "    response = openai.chat.completions.create(",
      '        model="gpt-4",',
      "        messages=[",
      '            {"role": "system", "content": full_prompt},',
      '            {"role": "user", "content": user_input},',
      "        ],",
      "    )",
      "",
      "    return response.choices[0].message.content",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  assert.ok(
    findings.some((f) => f.rule_id === "AI001"),
    "expected AI001 to trace taint across ordinary business logic between the request read and the LLM call",
  );
});

// ── Python receiver resolution (renamed SDK client variables) ───────────────

test("AI001 fires when the LLM client variable is not named client/llm/chain", () => {
  const dir = tempDir("secureai-py-receiver-");
  fs.writeFileSync(
    path.join(dir, "app.py"),
    [
      "from openai import OpenAI",
      "from flask import request",
      "",
      "gateway = OpenAI()",
      "",
      "def handle():",
      "    user_input = request.json['q']",
      "    reply = gateway.chat.completions.create(",
      '        model="gpt-4",',
      '        messages=[{"role": "system", "content": f"Answer: {user_input}"}],',
      "    )",
      "    return reply",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  assert.ok(
    findings.some((f) => f.rule_id === "AI001"),
    "expected AI001 to resolve `gateway` through its OpenAI() constructor binding",
  );
});

test("Python rules do not fire on a chain-shaped call in a file with no LLM SDK import", () => {
  const dir = tempDir("secureai-py-nollm-");
  fs.writeFileSync(
    path.join(dir, "etl.py"),
    [
      "from flask import request",
      "from mypipeline import chain",
      "",
      "def handle():",
      "    user_input = request.json['q']",
      "    return chain.invoke(user_input)",
      "",
    ].join("\n"),
  );

  const { findings } = scanPythonFiles(dir);
  assert.equal(
    findings.some((f) => f.rule_id === "AI001"),
    false,
    "a `chain.invoke` in a non-LLM file must not be treated as an LLM sink",
  );
});

// ── Non-production path segments (confidence.ts) ────────────────────────────

test("isTestFilePath matches prefixed segments like test-fixtures, not just suffixed ones", () => {
  for (const p of [
    "test-fixtures/vulnerable/app.ts",
    "ecosystem-tests/node/index.ts",
    "example-app/src/main.py",
    "packages/demo-server/server.ts",
    "src/__tests__/foo.ts",
  ]) {
    assert.equal(isTestFilePath(p), true, `${p} should be non-production`);
  }
  for (const p of [
    "src/attestation/verify.ts",
    "src/protest/index.ts",
    "src/sampler/rate.ts",
    "src/exemplar/main.py",
  ]) {
    assert.equal(isTestFilePath(p), false, `${p} must stay production code`);
  }
});

// ── BOM bare-identifier gating (bom.ts) ─────────────────────────────────────

test("AI-BOM does not flag bare o1/o3 identifiers but still catches quoted model IDs", () => {
  const dir = tempDir("secureai-bom-");
  fs.writeFileSync(
    path.join(dir, "app.ts"),
    [
      "const o1 = 5;",
      "const o3 = compute(o1);",
      "function compute(x) { return x * 2; }",
      "",
      'const model = "gpt-4-turbo";',
      'const reasoningModel = "o1-preview";',
      "",
    ].join("\n"),
  );

  const bom = generateBom(dir);
  const modelNames = bom.components.filter((c) => c.kind === "model").map((c) => c.name);
  assert.equal(modelNames.includes("o1"), false);
  assert.equal(modelNames.includes("o3"), false);
  assert.ok(modelNames.includes("gpt-4-turbo"));
  assert.ok(modelNames.includes("o1-preview"));
});

// ── RAG ambiguous-name gating (rag-context-injection.ts) ────────────────────

test("AI007 does not fire when a generic 'context' var has no retrieval call nearby", () => {
  const dir = tempDir("secureai-rag-generic-");
  fs.writeFileSync(
    path.join(dir, "route.ts"),
    `
    export async function handler(req: any) {
      const context = { locale: req.locale, theme: req.theme };
      const completion = await openai.chat.completions.create({
        messages: [
          { role: "system", content: \`App context: \${JSON.stringify(context)}\` },
          { role: "user", content: req.body.q },
        ],
      });
      return completion;
    }
    `,
  );

  const result = scanRepositoryDetailed(dir, { rules: ["AI007"] });
  assert.equal(result.findings.some((f) => f.rule_id === "AI007"), false);
});

test("AI007 fires when a generic 'results' var is assigned from a retrieval call", () => {
  const dir = tempDir("secureai-rag-retrieval-");
  fs.writeFileSync(
    path.join(dir, "route.ts"),
    `
    export async function handler(req: any) {
      const results = await vectorStore.similaritySearch(req.body.q);
      const completion = await openai.chat.completions.create({
        messages: [
          { role: "system", content: \`Use: \${results}\` },
          { role: "user", content: req.body.q },
        ],
      });
      return completion;
    }
    `,
  );

  const result = scanRepositoryDetailed(dir, { rules: ["AI007"] });
  const finding = result.findings.find((f) => f.rule_id === "AI007");
  assert.ok(finding, "expected AI007 to fire");
  assert.equal(finding.evidence, "heuristic");
});

// ── Vector-store ambiguous-client gating (vec-*-no-*.ts) ────────────────────

test("VEC001/VEC004 do not fire on plain Supabase table reads/writes with no vector signal", () => {
  const dir = tempDir("secureai-vec-supabase-plain-");
  fs.writeFileSync(
    path.join(dir, "orders.ts"),
    `
    export async function listOrders(userId: string) {
      const rows = await supabase.from("orders").search("status:open");
      await supabase.from("orders").insert({ userId, total: 42 });
      return rows;
    }
    `,
  );

  const result = scanRepositoryDetailed(dir, { rules: ["VEC001", "VEC004"] });
  assert.deepEqual(result.findings.map((f) => f.rule_id), []);
});

test("VEC001 fires on Supabase vector search once an embedding/vector signal is present", () => {
  const dir = tempDir("secureai-vec-supabase-vector-");
  fs.writeFileSync(
    path.join(dir, "search.ts"),
    `
    export async function searchDocs(embedding: number[]) {
      return supabase.from("docs").search({ vector: embedding, k: 5 });
    }
    `,
  );

  const result = scanRepositoryDetailed(dir, { rules: ["VEC001"] });
  assert.equal(result.findings.some((f) => f.rule_id === "VEC001"), true);
});

// ── Indirect prompt injection substring gating (indirect-prompt-injection.ts) ─

test("AI010 does not fire on a variable that merely contains the word 'fetch'", () => {
  const dir = tempDir("secureai-fetch-name-");
  fs.writeFileSync(
    path.join(dir, "route.ts"),
    `
    export async function handler(req: any) {
      const cfg = { fetch: true };
      const prefetchedIds = [1, 2, 3];
      const completion = await openai.chat.completions.create({
        messages: [{ role: "user", content: JSON.stringify({ cfg, prefetchedIds }) }],
      });
      return completion;
    }
    `,
  );

  const result = scanRepositoryDetailed(dir, { rules: ["AI010"] });
  assert.equal(result.findings.some((f) => f.rule_id === "AI010"), false);
});

// ── Structured-output bare-name gating (unvalidated-structured-output.ts) ───

test("AI012 does not fire on JSON.parse of a non-LLM variable merely named 'result'", () => {
  const dir = tempDir("secureai-structured-name-");
  fs.writeFileSync(
    path.join(dir, "route.ts"),
    `
    export function handler() {
      const result = buildReport();
      const parsed = JSON.parse(result);
      return parsed;
    }
    function buildReport() { return "{}"; }
    `,
  );

  const result = scanRepositoryDetailed(dir, { rules: ["AI012"] });
  assert.equal(result.findings.some((f) => f.rule_id === "AI012"), false);
});

// ── Catalog completeness (catalog.ts) ────────────────────────────────────────

test("DEP002 has a catalog entry so reports don't render blank OWASP/fix tags", () => {
  assert.ok(catalogFor("DEP002"), "expected a RULE_CATALOG entry for DEP002");
});

// ── Crash safety smoke test (llm-rule-utils.ts / sensitive-data-to-llm.ts) ──

test("scanning unresolvable/edge-case identifiers does not throw", () => {
  const dir = tempDir("secureai-crash-safety-");
  fs.writeFileSync(
    path.join(dir, "weird.ts"),
    `
    declare const unresolvableGlobal: any;
    export async function handler({ destructured }: any) {
      await openai.chat.completions.create({
        messages: [{ role: "user", content: JSON.stringify(unresolvableGlobal) }],
      });
      await openai.chat.completions.create({
        messages: [{ role: "user", content: JSON.stringify(destructured) }],
      });
    }
    `,
  );

  assert.doesNotThrow(() => scanRepositoryDetailed(dir));
});
