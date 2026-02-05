import type { Finding } from "./types.js";

export interface FindingExplanation {
  summary: string;
  whyRisky: string;
  howExploited: string;
  howToFix: string;
  codeExample: string;
}

export interface Explainer {
  explain(finding: Finding): FindingExplanation;
}

export type ExplanationProvider = (finding: Finding) => FindingExplanation;

const DEFAULT_EXPLANATIONS: Record<string, FindingExplanation> = {
  AI001: {
    summary: "User input flows directly into the LLM prompt.",
    whyRisky:
      "Untrusted input can alter system instructions or inject adversarial content into the prompt.",
    howExploited:
      "An attacker supplies crafted input that causes the model to ignore safety constraints or leak data.",
    howToFix:
      "Use role separation, encode user input, and apply strict validation or allowlists for inputs.",
    codeExample: `// Bad
const prompt = "Summarize: " + req.body.text;

// Good
const prompt = [
  { role: "system", content: "Summarize the user input safely." },
  { role: "user", content: String(req.body.text) },
];`,
  },
  AI002: {
    summary: "Sensitive prompt or response data is logged.",
    whyRisky:
      "Logs often end up in shared systems, exposing credentials or user data to unintended parties.",
    howExploited:
      "An attacker with log access can retrieve tokens, passwords, or proprietary data embedded in prompts.",
    howToFix:
      "Avoid logging prompts or responses, or redact sensitive fields before logging.",
    codeExample: `// Bad
logger.info({ prompt, email: user.email }, "LLM request");

// Good
logger.info({ requestId }, "LLM request");`,
  },
  AI003: {
    summary: "LLM calls are made before authentication checks.",
    whyRisky:
      "Unauthenticated callers can invoke LLM actions, leading to data exposure or abuse.",
    howExploited:
      "An attacker hits the endpoint directly and triggers LLM usage without valid credentials.",
    howToFix:
      "Enforce authentication and authorization before any LLM invocation.",
    codeExample: `// Bad
app.post("/ask", async (req, res) => {
  const result = await openai.chat.completions.create({ messages });
});

// Good
app.post("/ask", requireAuth, async (req, res) => {
  const result = await openai.chat.completions.create({ messages });
});`,
  },
  AI004: {
    summary: "Large user context is sent directly to an LLM.",
    whyRisky:
      "User, session, or profile objects may contain PII or secrets that should not leave your system.",
    howExploited:
      "Attackers can prompt the model to surface sensitive attributes or exfiltrate data included in context.",
    howToFix:
      "Send only necessary fields and redact or tokenize sensitive values before LLM calls.",
    codeExample: `// Bad
await openai.chat.completions.create({ messages: [{ role: "user", content: JSON.stringify(user) }] });

// Good
const minimal = { name: user.name, plan: user.plan };
await openai.chat.completions.create({ messages: [{ role: "user", content: JSON.stringify(minimal) }] });`,
  },
};

export class StaticExplainer implements Explainer {
  explain(finding: Finding): FindingExplanation {
    const fallback: FindingExplanation = {
      summary: finding.title,
      whyRisky: "This pattern can introduce security risk when untrusted data is involved.",
      howExploited:
        "An attacker may manipulate inputs or control execution flow to gain unintended access.",
      howToFix:
        "Review data flow, validate inputs, and apply least-privilege checks before LLM usage.",
      codeExample: "// Add authentication, validation, and data minimization as applicable.",
    };

    return DEFAULT_EXPLANATIONS[finding.rule_id] ?? fallback;
  }
}

export class PluggableExplainer implements Explainer {
  private provider: ExplanationProvider;

  constructor(provider?: ExplanationProvider) {
    this.provider = provider ?? ((finding) => new StaticExplainer().explain(finding));
  }

  explain(finding: Finding): FindingExplanation {
    return this.provider(finding);
  }
}
