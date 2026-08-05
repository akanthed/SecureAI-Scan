import test from "node:test";
import assert from "node:assert/strict";
import { Project, SyntaxKind } from "ts-morph";

import { getCallsWithin, getFileCalls, getFileFunctions } from "../dist/utils/ast.js";

/**
 * The file index replaced ~20 independent AST walks per file, and
 * `getCallsWithin` replaced subtree walks with a binary search over
 * precomputed compiler spans. That is a big speedup (217s -> 63s on
 * vercel/ai) resting on one assumption: pre-order document order means a
 * node's descendants are a contiguous run of the index. If that assumption
 * ever breaks, rules silently stop seeing calls — a scanner that goes quiet
 * is the worst failure mode there is, so it gets asserted directly against
 * ts-morph's own traversal rather than trusted.
 */

const SOURCE = `
import OpenAI from "openai";

const client = new OpenAI();

export function outer(req) {
  const a = one(req.body);

  const nested = async (x) => {
    const b = two(x);
    return client.chat.completions.create({ messages: [{ role: "user", content: b }] });
  };

  class Inner {
    method() {
      return three(four(five()));
    }
  }

  return { nested, Inner, a, tagged: tag\`\${six()}\` };
}

export const arrow = () => seven(eight());

function decoy() {
  // a call in a comment should not count: nine()
  return "ten()";
}
`;

function makeFile() {
  const project = new Project({ useInMemoryFileSystem: true });
  return project.createSourceFile("sample.ts", SOURCE);
}

test("the file call index matches ts-morph's own descendant walk exactly", () => {
  const file = makeFile();
  const expected = file.getDescendantsOfKind(SyntaxKind.CallExpression);
  const actual = getFileCalls(file);

  assert.equal(actual.length, expected.length);
  assert.deepEqual(
    actual.map((c) => c.getText()),
    expected.map((c) => c.getText()),
    "index must preserve document order, not just membership",
  );
});

test("the file function index matches ts-morph's own descendant walk exactly", () => {
  const file = makeFile();
  const expected = file
    .getDescendants()
    .filter(
      (n) =>
        n.getKind() === SyntaxKind.FunctionDeclaration ||
        n.getKind() === SyntaxKind.FunctionExpression ||
        n.getKind() === SyntaxKind.ArrowFunction ||
        n.getKind() === SyntaxKind.MethodDeclaration,
    );
  const actual = getFileFunctions(file);

  assert.equal(actual.length, expected.length);
  assert.deepEqual(actual.map((n) => n.getPos()), expected.map((n) => n.getPos()));
});

test("getCallsWithin matches a real subtree walk for every function in the file", () => {
  const file = makeFile();
  const functions = getFileFunctions(file);

  // A file with only top-level functions would not exercise the containment
  // boundaries at all; the fixture nests an arrow and a class method inside
  // `outer` precisely so the slice has to end in the right place.
  assert.ok(functions.length >= 5, "fixture must contain nested functions");

  for (const fn of functions) {
    const expected = fn.getDescendantsOfKind(SyntaxKind.CallExpression).map((c) => c.getText());
    const actual = getCallsWithin(fn).map((c) => c.getText());
    assert.deepEqual(actual, expected, `mismatch inside: ${fn.getKindName()} @ ${fn.getPos()}`);
  }
});

test("getCallsWithin excludes calls in sibling scopes", () => {
  const file = makeFile();
  const arrow = getFileFunctions(file).find((fn) => fn.getText().includes("seven"));
  assert.ok(arrow, "fixture must contain the standalone arrow function");

  const texts = getCallsWithin(arrow).map((c) => c.getText());
  assert.ok(texts.some((t) => t.startsWith("seven(")));
  assert.ok(!texts.some((t) => t.startsWith("one(") || t.startsWith("three(")));
});
