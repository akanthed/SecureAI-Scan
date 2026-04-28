import { Node, SyntaxKind } from "ts-morph";

export const LLM_CALLEE_PATTERNS = [
  "openai",
  "anthropic",
  "google",
  "gemini",
  "genai",
  "langchain",
  "llamaindex",
  "bedrock",
  "mistral",
  "cohere",
];

export function isLikelyLlmCall(node: Node): boolean {
  if (!Node.isCallExpression(node)) {
    return false;
  }
  const expressionText = node.getExpression().getText().toLowerCase();
  return LLM_CALLEE_PATTERNS.some((pattern) => expressionText.includes(pattern));
}

export function getObjectProperty(
  objectNode: Node,
  propertyName: string,
): Node | undefined {
  if (!Node.isObjectLiteralExpression(objectNode)) {
    return undefined;
  }
  const property = objectNode
    .getProperties()
    .find(
      (prop) =>
        Node.isPropertyAssignment(prop) &&
        prop.getNameNode().getText().replace(/['"]/g, "") === propertyName,
    );
  if (!property || !Node.isPropertyAssignment(property)) {
    return undefined;
  }
  return property.getInitializer();
}

export function getLlmPromptNodes(call: Node): Node[] {
  if (!Node.isCallExpression(call)) {
    return [];
  }

  const args = call.getArguments();
  if (args.length === 0) {
    return [];
  }

  const firstArg = args[0];
  if (!Node.isObjectLiteralExpression(firstArg)) {
    return args;
  }

  const nodes: Node[] = [];
  const prompt = getObjectProperty(firstArg, "prompt");
  if (prompt) {
    nodes.push(prompt);
  }

  const messages = getObjectProperty(firstArg, "messages");
  if (messages && Node.isArrayLiteralExpression(messages)) {
    for (const element of messages.getElements()) {
      if (!Node.isObjectLiteralExpression(element)) {
        continue;
      }
      const content = getObjectProperty(element, "content");
      if (content) {
        nodes.push(content);
      }
    }
  }

  return nodes.length > 0 ? nodes : args;
}

export function getStringValue(node: Node): string | undefined {
  if (Node.isStringLiteral(node) || Node.isNoSubstitutionTemplateLiteral(node)) {
    return node.getLiteralText();
  }
  return undefined;
}

export function containsIdentifierNamed(node: Node, names: Set<string>): boolean {
  if (Node.isIdentifier(node) && names.has(node.getText().toLowerCase())) {
    return true;
  }
  return node
    .getDescendantsOfKind(SyntaxKind.Identifier)
    .some((identifier) => names.has(identifier.getText().toLowerCase()));
}

export function isRequestLikeNode(node: Node): boolean {
  const text = node.getText().toLowerCase();
  return /\b(req|request|ctx)\s*\./.test(text) || /\b(body|query|params)\b/.test(text);
}

