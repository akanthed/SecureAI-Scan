import path from "node:path";
import { BinaryExpression, CallExpression, Node, SourceFile, SyntaxKind } from "ts-morph";

export function isStringConcatenation(node: Node): node is BinaryExpression {
  return (
    Node.isBinaryExpression(node) &&
    node.getOperatorToken().getKind() === SyntaxKind.PlusToken
  );
}

export function getNodeLine(node: Node): number {
  return node.getSourceFile().getLineAndColumnAtPos(node.getStart()).line;
}

export function getRelativeFilePath(
  rootPath: string,
  sourceFile: SourceFile,
): string {
  const filePath = sourceFile.getFilePath();
  return path.relative(rootPath, filePath);
}

export function isPotentialPromptArgument(node: Node): boolean {
  return isStringConcatenation(node);
}

export function isFunctionLike(node: Node): boolean {
  return (
    Node.isFunctionDeclaration(node) ||
    Node.isFunctionExpression(node) ||
    Node.isArrowFunction(node) ||
    Node.isMethodDeclaration(node)
  );
}

interface FileIndex {
  calls: CallExpression[];
  /** `calls[i]`'s compiler-node span, captured during the walk. */
  callPos: number[];
  callEnd: number[];
  functions: Node[];
}

const fileIndexCache = new WeakMap<SourceFile, FileIndex>();

/**
 * Every rule used to run its own `getDescendantsOfKind(CallExpression)` or
 * `getDescendants()` over each file. With ~20 rules that is ~20 full AST walks
 * per file, and a CPU profile of a 5,691-file repo attributed ~95s of a 150s
 * scan to descendant traversal alone — more than everything else combined,
 * type resolution included. One pre-order walk fills every bucket instead.
 */
function fileIndex(sourceFile: SourceFile): FileIndex {
  const cached = fileIndexCache.get(sourceFile);
  if (cached) return cached;

  const index: FileIndex = { calls: [], callPos: [], callEnd: [], functions: [] };
  sourceFile.forEachDescendant((node) => {
    if (Node.isCallExpression(node)) {
      index.calls.push(node);
      index.callPos.push(node.compilerNode.pos);
      index.callEnd.push(node.compilerNode.end);
    } else if (isFunctionLike(node)) {
      index.functions.push(node);
    }
  });

  fileIndexCache.set(sourceFile, index);
  return index;
}

/** All call expressions in a file, in document order. Memoized per file. */
export function getFileCalls(sourceFile: SourceFile): CallExpression[] {
  return fileIndex(sourceFile).calls;
}

/** All function/method/arrow nodes in a file, in document order. Memoized per file. */
export function getFileFunctions(sourceFile: SourceFile): Node[] {
  return fileIndex(sourceFile).functions;
}

/**
 * Call expressions inside `node`. The file index is in pre-order, so every
 * descendant of a node occupies one contiguous run of it — a binary search over
 * the precomputed spans beats re-walking the subtree, which matters because
 * rules ask this of every function and nested functions are otherwise
 * re-walked once per enclosing scope. Spans come from the compiler node
 * directly: `getStart()` rescans leading trivia on every call, which made an
 * earlier version of this slower than the walk it replaced.
 */
export function getCallsWithin(node: Node): CallExpression[] {
  const index = fileIndex(node.getSourceFile());
  const pos = node.compilerNode.pos;
  const end = node.compilerNode.end;

  let lo = 0;
  let hi = index.callPos.length;
  while (lo < hi) {
    const mid = (lo + hi) >>> 1;
    if (index.callPos[mid]! < pos) lo = mid + 1;
    else hi = mid;
  }

  const result: CallExpression[] = [];
  for (let i = lo; i < index.callPos.length && index.callEnd[i]! <= end; i++) {
    result.push(index.calls[i]!);
  }
  return result;
}
