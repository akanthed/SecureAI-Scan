import { Node, SyntaxKind } from "ts-morph";
import type { Finding, Rule, RuleContext } from "../types.js";
import { getNodeLine, getRelativeFilePath } from "../../utils/ast.js";
import { calculateConfidence } from "../confidence.js";

type Pattern = {
  id: string;
  title: string;
  matcher: (expressionText: string) => boolean;
};

const PATTERNS: Pattern[] = [
  {
    id: "LLM_OPENAI_CHAT_COMPLETIONS_CREATE",
    title: "OpenAI chat.completions.create usage",
    matcher: (text) => text.includes("openai.chat.completions.create"),
  },
  {
    id: "LLM_OPENAI_CHATCOMPLETION_CREATE",
    title: "OpenAI ChatCompletion.create usage",
    matcher: (text) => text.includes("openai.chatcompletion.create"),
  },
  {
    id: "LLM_ANTHROPIC_MESSAGES",
    title: "Anthropic messages client usage",
    matcher: (text) =>
      text.includes("anthropic.messages.create") ||
      text.includes(".messages.create"),
  },
  {
    id: "LLM_GEMINI_GENERATECONTENT",
    title: "Gemini generateContent usage",
    matcher: (text) =>
      text.includes("generatecontent") || text.includes(".generatecontent"),
  },
];

export const ruleLlmUsageDetect: Rule = {
  id: "AI100",
  title: "LLM SDK usage detection",
  severity: "low",
  run(context: RuleContext): Finding[] {
    const findings: Finding[] = [];

    for (const sourceFile of context.sourceFiles) {
      const calls = sourceFile.getDescendantsOfKind(
        SyntaxKind.CallExpression,
      );

      for (const call of calls) {
        const expression = call.getExpression();
        const expressionText = expression.getText().toLowerCase();

        for (const pattern of PATTERNS) {
          if (!pattern.matcher(expressionText)) {
            continue;
          }

          findings.push({
            rule_id: pattern.id,
            title: pattern.title,
            severity: "low",
            file: getRelativeFilePath(context.rootPath, sourceFile),
            line: getNodeLine(call),
            summary: "LLM SDK usage detected.",
            description: "LLM SDK usage detected.",
            recommendation:
              "Review the call to ensure prompts, inputs, and outputs are securely handled.",
            confidence: calculateConfidence({
              directUserInput: false,
              stringConcatOrTemplate: false,
              requestObjectSource: false,
              confirmedLlmCall: true,
            }),
          });
        }
      }
    }

    return findings;
  },
};
