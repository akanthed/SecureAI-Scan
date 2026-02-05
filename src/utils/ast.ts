import path from "node:path";
import { BinaryExpression, Node, SourceFile, SyntaxKind } from "ts-morph";

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
