import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

import {
  parsePythonAst,
  pythonCallName,
  pythonNodeContainsText,
  pythonTargetText,
} from "../dist/scanner/python-ast.js";
import { analyzePythonSource } from "../dist/scanner/python-source.js";
import { scanPythonFiles } from "../dist/scanner/python-scanner.js";

function tempRepo(files) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-python-ast-"));
  for (const [name, source] of Object.entries(files)) {
    const full = path.join(root, name);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, source);
  }
  return root;
}

test("Python AST indexes calls, attributes, tuple targets, decorators, and keywords", () => {
  const ast = parsePythonAst(`
from openai import OpenAI
client = OpenAI()

@router.post("/chat")
@jwt_required()
async def chat(request):
    self.prompt, request_id = request.json["q"], request.json["id"]
    return await client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": self.prompt}],
    )
`);

  assert.equal(ast.hasSyntaxErrors, false);
  assert.deepEqual(ast.assignments[1].targets.map(pythonTargetText), ["self.prompt", "request_id"]);
  const llmCall = ast.calls.find((call) => pythonCallName(call).endsWith("completions.create"));
  assert.ok(llmCall);
  assert.equal(llmCall.keywords.get("model")?.text, '"gpt-4o-mini"');
  assert.ok(pythonNodeContainsText(llmCall.node, "self.prompt"));
  assert.equal(ast.functions[0].decorators.length, 2);
  assert.equal(ast.enclosingFunction(llmCall.node)?.name, "chat");
});

test("comments and strings containing fake imports or calls never become AST nodes", () => {
  const ast = parsePythonAst(`
text = "from openai import OpenAI; client.chat.completions.create()"
# import anthropic
print(text)
`);
  assert.equal(ast.imports.length, 0);
  assert.deepEqual(ast.calls.map(pythonCallName), ["print"]);
});

test("malformed Python yields a recoverable AST instead of aborting the scan", () => {
  const ast = parsePythonAst("from openai import OpenAI\nclient = OpenAI(\n");
  assert.equal(ast.hasSyntaxErrors, true);
  assert.ok(ast.imports.length === 1);
});

test("AI001 traces attribute and tuple-assignment request taint through AST nodes", () => {
  const root = tempRepo({
    "app.py": `
from flask import request
from openai import OpenAI
client = OpenAI()

def handler():
    self.prompt, request_id = request.json["q"], request.json["id"]
    return client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": self.prompt}],
    )
`,
  });
  try {
    const findings = scanPythonFiles(root).findings;
    assert.ok(findings.some((finding) => finding.rule_id === "AI001" && finding.evidence === "likely"));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("fake LLM syntax in comments and docstrings produces no Python findings", () => {
  const root = tempRepo({
    "docs.py": `
"""
from openai import OpenAI
client = OpenAI()
prompt = request.json["q"]
client.chat.completions.create(messages=[{"role": "user", "content": prompt}])
"""
# from anthropic import Anthropic
# client.messages.create(messages=[])
value = "litellm.completion(prompt=request.json['q'])"
`,
  });
  try {
    assert.deepEqual(scanPythonFiles(root).findings, []);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("analyzed Python source exposes the same production AST used by rules", () => {
  const src = analyzePythonSource("x = fetch()\n");
  assert.equal(src.ast.assignments.length, 1);
  assert.equal(pythonCallName(src.ast.calls[0]), "fetch");
});

test("VEC001 recognizes vector SDK filter aliases and explicit keyword expansion", () => {
  const root = tempRepo({
    "vectors.py": `
def filtered_searches(store, vector, tenant_filter):
    store.search(vector, expr=tenant_filter)
    store.search(vector, query_filter=tenant_filter)
    store.search(vector, metadata=tenant_filter)
    store.search(vector, metadata_filters=tenant_filter)

    kwargs = {}
    kwargs["filter"] = tenant_filter
    store.search(vector, **kwargs)

def unfiltered_search(store, vector):
    return store.search(vector)
`,
  });
  try {
    const findings = scanPythonFiles(root).findings.filter((finding) => finding.rule_id === "VEC001");
    assert.equal(findings.length, 1);
    assert.equal(findings[0].line, 13);
    assert.equal(findings[0].evidence, "likely");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
