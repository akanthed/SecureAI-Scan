import path from "node:path";
import {
  Node,
  Project,
  SourceFile,
  SyntaxKind,
  VariableDeclaration,
} from "ts-morph";

export interface AstProject {
  project: Project;
  sourceFiles: SourceFile[];
}

export function createAstProject(rootPath: string): AstProject {
  const project = new Project({
    skipAddingFilesFromTsConfig: true,
  });

  const normalizedRoot = path.resolve(rootPath);
  project.addSourceFilesAtPaths([
    path.join(normalizedRoot, "**/*.ts"),
    path.join(normalizedRoot, "**/*.js"),
  ]);

  return {
    project,
    sourceFiles: project.getSourceFiles(),
  };
}

export function findFunctionCalls(sourceFile: SourceFile, name: string): Node[] {
  const calls = sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression);
  const target = name.toLowerCase();
  return calls.filter((call) =>
    call.getExpression().getText().toLowerCase().includes(target),
  );
}

export function findStringConcatenations(sourceFile: SourceFile): Node[] {
  return sourceFile
    .getDescendantsOfKind(SyntaxKind.BinaryExpression)
    .filter(
      (expr) => expr.getOperatorToken().getKind() === SyntaxKind.PlusToken,
    );
}

export interface VariableOrigin {
  variable: string;
  initializerText: string | null;
  source: "literal" | "identifier" | "call" | "unknown";
}

export function trackVariableOrigins(
  sourceFile: SourceFile,
): VariableOrigin[] {
  const declarations = sourceFile.getDescendantsOfKind(
    SyntaxKind.VariableDeclaration,
  );

  return declarations.map((declaration): VariableOrigin => {
    const name = declaration.getName();
    const initializer = declaration.getInitializer();
    if (!initializer) {
      return {
        variable: name,
        initializerText: null,
        source: "unknown",
      };
    }

    if (Node.isStringLiteral(initializer) || Node.isNoSubstitutionTemplateLiteral(initializer)) {
      return {
        variable: name,
        initializerText: initializer.getText(),
        source: "literal",
      };
    }

    if (Node.isIdentifier(initializer)) {
      return {
        variable: name,
        initializerText: initializer.getText(),
        source: "identifier",
      };
    }

    if (Node.isCallExpression(initializer)) {
      return {
        variable: name,
        initializerText: initializer.getText(),
        source: "call",
      };
    }

    return {
      variable: name,
      initializerText: initializer.getText(),
      source: "unknown",
    };
  });
}
