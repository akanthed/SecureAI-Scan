import { parsePythonAst, type PythonAst } from "./python-ast.js";

/** The Tree-sitter syntax tree plus physical line count for rule dispatch. */
export interface PythonSource {
  ast: PythonAst;
  lineCount: number;
}

export function analyzePythonSource(rawText: string): PythonSource {
  return {
    ast: parsePythonAst(rawText),
    lineCount: rawText.split(/\r?\n/).length,
  };
}
