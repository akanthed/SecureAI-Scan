# SecureAI-Scan Report

## Summary

Total findings: 19

## Findings Table

| ID | Severity | Confidence | File | Line | Summary |
| --- | --- | --- | --- | --- | --- |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | examples\vulnerable.ts | 10 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | examples\vulnerable.ts | 15 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\safe\hardcoded_key.ts | 7 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\safe\llm_before_auth.ts | 15 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\safe\pii_to_llm.ts | 19 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\safe\prompt_injection.ts | 14 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\vulnerable\hardcoded_key.ts | 7 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\vulnerable\llm_before_auth.ts | 8 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\vulnerable\pii_to_llm.ts | 10 | LLM SDK usage detected. |
| LLM_OPENAI_CHAT_COMPLETIONS_CREATE | 🟢 LOW | 0.20 | test-fixtures\vulnerable\prompt_injection.ts | 10 | LLM SDK usage detected. |
| AI002 | 🟠 HIGH | 0.30 | examples\vulnerable.ts | 5 | Prompt or response data is logged. |
| AI003 | 🔴 CRITICAL | 0.40 | examples\vulnerable.ts | 10 | LLM call occurs before auth checks. |
| AI003 | 🔴 CRITICAL | 0.40 | examples\vulnerable.ts | 15 | LLM call occurs before auth checks. |
| AI003 | 🔴 CRITICAL | 0.40 | test-fixtures\vulnerable\llm_before_auth.ts | 8 | LLM call occurs before auth checks. |
| AI003 | 🔴 CRITICAL | 0.40 | test-fixtures\vulnerable\pii_to_llm.ts | 10 | LLM call occurs before auth checks. |
| AI003 | 🔴 CRITICAL | 0.40 | test-fixtures\vulnerable\prompt_injection.ts | 10 | LLM call occurs before auth checks. |
| AI004 | 🟠 HIGH | 0.70 | examples\vulnerable.ts | 17 | Large user context sent directly to LLM. |
| AI004 | 🟠 HIGH | 0.50 | test-fixtures\safe\pii_to_llm.ts | 21 | Large user context sent directly to LLM. |
| AI004 | 🟠 HIGH | 0.70 | test-fixtures\vulnerable\pii_to_llm.ts | 13 | Large user context sent directly to LLM. |

## Details

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: examples\vulnerable.ts
- Line: 10
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: examples\vulnerable.ts
- Line: 15
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\safe\hardcoded_key.ts
- Line: 7
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\safe\llm_before_auth.ts
- Line: 15
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\safe\pii_to_llm.ts
- Line: 19
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\safe\prompt_injection.ts
- Line: 14
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\vulnerable\hardcoded_key.ts
- Line: 7
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\vulnerable\llm_before_auth.ts
- Line: 8
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\vulnerable\pii_to_llm.ts
- Line: 10
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### LLM_OPENAI_CHAT_COMPLETIONS_CREATE: OpenAI chat.completions.create usage

- Severity: 🟢 LOW
- File: test-fixtures\vulnerable\prompt_injection.ts
- Line: 10
- Confidence: 0.20
- Summary: LLM SDK usage detected.

LLM SDK usage detected.

Recommendation: Review the call to ensure prompts, inputs, and outputs are securely handled.

### AI002: Sensitive prompt logging

- Severity: 🟠 HIGH
- File: examples\vulnerable.ts
- Line: 5
- Confidence: 0.30
- Summary: Prompt or response data is logged.

Prompt content or LLM responses are logged alongside potentially sensitive fields.

Recommendation: Avoid logging prompt/response data or redact sensitive fields like email, token, password, or apiKey.

### AI003: LLM call before authentication

- Severity: 🔴 CRITICAL
- File: examples\vulnerable.ts
- Line: 10
- Confidence: 0.40
- Summary: LLM call occurs before auth checks.

LLM call occurs in a request handler before authentication checks.

Recommendation: Ensure authentication/authorization runs before invoking LLMs in request handlers.

### AI003: LLM call before authentication

- Severity: 🔴 CRITICAL
- File: examples\vulnerable.ts
- Line: 15
- Confidence: 0.40
- Summary: LLM call occurs before auth checks.

LLM call occurs in a request handler before authentication checks.

Recommendation: Ensure authentication/authorization runs before invoking LLMs in request handlers.

### AI003: LLM call before authentication

- Severity: 🔴 CRITICAL
- File: test-fixtures\vulnerable\llm_before_auth.ts
- Line: 8
- Confidence: 0.40
- Summary: LLM call occurs before auth checks.

LLM call occurs in a request handler before authentication checks.

Recommendation: Ensure authentication/authorization runs before invoking LLMs in request handlers.

### AI003: LLM call before authentication

- Severity: 🔴 CRITICAL
- File: test-fixtures\vulnerable\pii_to_llm.ts
- Line: 10
- Confidence: 0.40
- Summary: LLM call occurs before auth checks.

LLM call occurs in a request handler before authentication checks.

Recommendation: Ensure authentication/authorization runs before invoking LLMs in request handlers.

### AI003: LLM call before authentication

- Severity: 🔴 CRITICAL
- File: test-fixtures\vulnerable\prompt_injection.ts
- Line: 10
- Confidence: 0.40
- Summary: LLM call occurs before auth checks.

LLM call occurs in a request handler before authentication checks.

Recommendation: Ensure authentication/authorization runs before invoking LLMs in request handlers.

### AI004: Sensitive data sent to LLM

- Severity: 🟠 HIGH
- File: examples\vulnerable.ts
- Line: 17
- Confidence: 0.70
- Summary: Large user context sent directly to LLM.

Potential PII exposure risk: user/profile/session data is sent to an LLM without minimization.

Recommendation: Minimize or redact sensitive fields before sending to LLMs; send only necessary attributes.

### AI004: Sensitive data sent to LLM

- Severity: 🟠 HIGH
- File: test-fixtures\safe\pii_to_llm.ts
- Line: 21
- Confidence: 0.50
- Summary: Large user context sent directly to LLM.

Potential PII exposure risk: user/profile/session data is sent to an LLM without minimization.

Recommendation: Minimize or redact sensitive fields before sending to LLMs; send only necessary attributes.

### AI004: Sensitive data sent to LLM

- Severity: 🟠 HIGH
- File: test-fixtures\vulnerable\pii_to_llm.ts
- Line: 13
- Confidence: 0.70
- Summary: Large user context sent directly to LLM.

Potential PII exposure risk: user/profile/session data is sent to an LLM without minimization.

Recommendation: Minimize or redact sensitive fields before sending to LLMs; send only necessary attributes.
