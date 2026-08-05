import Parser from "tree-sitter";
import Python from "tree-sitter-python";

export type PythonNode = Parser.SyntaxNode;

export interface PythonAssignmentNode {
  node: PythonNode;
  targets: PythonNode[];
  value: PythonNode;
}

export interface PythonCallNode {
  node: PythonNode;
  function: PythonNode;
  arguments: PythonNode[];
  keywords: Map<string, PythonNode>;
}

export interface PythonFunctionNode {
  node: PythonNode;
  name: string;
  body: PythonNode;
  decorators: PythonNode[];
}

export interface PythonAst {
  root: PythonNode;
  calls: PythonCallNode[];
  assignments: PythonAssignmentNode[];
  functions: PythonFunctionNode[];
  imports: PythonNode[];
  strings: PythonNode[];
  hasSyntaxErrors: boolean;
  callsAtLine(line: number): PythonCallNode[];
  assignmentsBefore(line: number, lowerBound?: number): PythonAssignmentNode[];
  enclosingFunction(node: PythonNode): PythonFunctionNode | undefined;
}

const parser = new Parser();
parser.setLanguage(Python as unknown as Parser.Language);

function walk(node: PythonNode, visit: (node: PythonNode) => void): void {
  visit(node);
  for (const child of node.namedChildren) walk(child, visit);
}

function assignmentTargets(node: PythonNode): PythonNode[] {
  const left = node.childForFieldName("left");
  if (!left) return [];
  if (left.type === "pattern_list" || left.type === "tuple" || left.type === "list_pattern") {
    return left.namedChildren.filter(
      (child) => child.type === "identifier" || child.type === "attribute" || child.type === "subscript",
    );
  }
  return [left];
}

function callInfo(node: PythonNode): PythonCallNode | undefined {
  const fn = node.childForFieldName("function");
  const argsNode = node.childForFieldName("arguments");
  if (!fn || !argsNode) return undefined;

  const arguments_: PythonNode[] = [];
  const keywords = new Map<string, PythonNode>();
  for (const child of argsNode.namedChildren) {
    if (child.type === "keyword_argument") {
      const name = child.childForFieldName("name")?.text;
      const value = child.childForFieldName("value");
      if (name && value) keywords.set(name, value);
    } else {
      arguments_.push(child);
    }
  }
  return { node, function: fn, arguments: arguments_, keywords };
}

function decoratorsFor(node: PythonNode): PythonNode[] {
  const parent = node.parent;
  if (parent?.type !== "decorated_definition") return [];
  return parent.namedChildren.filter((child) => child.type === "decorator");
}

function contains(outer: PythonNode, inner: PythonNode): boolean {
  return outer.startIndex <= inner.startIndex && outer.endIndex >= inner.endIndex;
}

export function parsePythonAst(source: string): PythonAst {
  parser.reset();
  const tree = parser.parse(source);
  const root = tree.rootNode;
  const calls: PythonCallNode[] = [];
  const assignments: PythonAssignmentNode[] = [];
  const functions: PythonFunctionNode[] = [];
  const imports: PythonNode[] = [];
  const strings: PythonNode[] = [];

  walk(root, (node) => {
    if (node.type === "call") {
      const call = callInfo(node);
      if (call) calls.push(call);
      return;
    }
    if (node.type === "assignment" || node.type === "augmented_assignment" || node.type === "named_expression") {
      const value = node.childForFieldName("right") ?? node.childForFieldName("value");
      const targets = assignmentTargets(node);
      if (value && targets.length > 0) assignments.push({ node, targets, value });
      return;
    }
    if (node.type === "function_definition") {
      const name = node.childForFieldName("name")?.text;
      const body = node.childForFieldName("body");
      if (name && body) functions.push({ node, name, body, decorators: decoratorsFor(node) });
      return;
    }
    if (node.type === "import_statement" || node.type === "import_from_statement") {
      imports.push(node);
      return;
    }
    if (node.type === "string" || node.type === "concatenated_string") strings.push(node);
  });

  const callsByLine = new Map<number, PythonCallNode[]>();
  for (const call of calls) {
    const line = call.node.startPosition.row;
    const bucket = callsByLine.get(line);
    if (bucket) bucket.push(call);
    else callsByLine.set(line, [call]);
  }

  return {
    root,
    calls,
    assignments,
    functions,
    imports,
    strings,
    hasSyntaxErrors: root.hasError,
    callsAtLine: (line: number) => callsByLine.get(line) ?? [],
    assignmentsBefore: (line: number, lowerBound = 0) =>
      assignments.filter(
        (assignment) =>
          assignment.node.startPosition.row >= lowerBound && assignment.node.startPosition.row <= line,
      ),
    enclosingFunction: (node: PythonNode) => {
      let current: PythonNode | null = node.parent;
      while (current) {
        if (current.type === "function_definition") {
          return functions.find((fn) => fn.node.id === current!.id);
        }
        current = current.parent;
      }
      return functions.find((fn) => contains(fn.body, node));
    },
  };
}

export function pythonTargetText(node: PythonNode): string {
  return node.text.replace(/\s*\.\s*/g, ".").trim();
}

function callableName(node: PythonNode): string {
  if (node.type === "identifier") return node.text;
  if (node.type === "attribute") {
    const object = node.childForFieldName("object");
    const attribute = node.childForFieldName("attribute");
    if (object && attribute) return `${callableName(object)}.${attribute.text}`;
  }
  if (node.type === "call") {
    const fn = node.childForFieldName("function");
    if (fn) return callableName(fn);
  }
  if (node.type === "subscript") {
    const value = node.childForFieldName("value");
    if (value) return callableName(value);
  }
  return node.text.replace(/\s+/g, "");
}

export function pythonCallName(call: PythonCallNode): string {
  return callableName(call.function);
}

export function pythonNodeContainsText(node: PythonNode, value: string): boolean {
  if (pythonTargetText(node) === value) return true;
  let found = false;
  walk(node, (child) => {
    if (child.type === "identifier" || child.type === "attribute") {
      if (pythonTargetText(child) === value) found = true;
    }
  });
  return found;
}

export function pythonDescendants(node: PythonNode, types: string | Set<string>): PythonNode[] {
  const accepted = typeof types === "string" ? new Set([types]) : types;
  const result: PythonNode[] = [];
  walk(node, (child) => {
    if (child.id !== node.id && accepted.has(child.type)) result.push(child);
  });
  return result;
}
