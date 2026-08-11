# OWASP Top 10 for LLM Applications 2026 Coverage

SecureAI-Scan provides launch-week mapping to the official [OWASP Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/). This page states what the scanner can establish from source code today. A category mapping means the listed rule detects a concrete risk within that category; it does not mean static analysis can detect every scenario OWASP describes.

| Risk | Current static signals | Boundary |
|---|---|---|
| LLM01 Prompt Injection | AI001, AI007, AI010, MCP001, MCP007–009, SKL001–003 | Text, RAG, HTTP, MCP, and Agent Skill trust flows are covered. Pixel/audio/video steganography requires modality-specific analysis. |
| LLM02 Sensitive Information Disclosure | AI002, AI004, MCP005, SKL005 | Covers prompt/secret logging, oversharing to models, and committed or exfiltrated credentials. Model memorization, inference side channels, and runtime disclosure require dynamic controls. |
| LLM03 Excessive Agency | AI006, AI011 | Covers high-impact tools without approval and inter-agent trust elevation. Downstream IAM scope and runtime autonomy budgets are not fully inferable from application source. |
| LLM04 Supply Chain | MCP002, MCP004, MCP006, MCP010, SKL004, DEP001–003 | Covers MCP/skill packages, transport, commands, typosquats, malicious releases, and critical advisories. Model, adapter, dataset, and signing provenance are planned gaps. |
| LLM05 Data and Model Poisoning | VEC003 | Covers user-controlled ingestion into shared vector stores. Training/fine-tuning pipelines, model artifacts, and continuous-learning feedback loops remain gaps. |
| LLM06 Unbounded Consumption | AI003, AI009, VEC002 | Covers unauthenticated model use, unbounded prompt/output limits, and user-controlled retrieval size. Aggregate budgets, reasoning loops, and agent circuit breakers remain gaps. |
| LLM07 Misinformation | No static rule | Output truth, grounding quality, and human overreliance are runtime/process concerns. SecureAI-Scan reports this boundary rather than stretching a heuristic into a finding. |
| LLM08 Hidden Context Exposure | AI008 | Covers credentials and credential-shaped values embedded in system prompts. Extraction behavior and reliance on hidden policy secrecy require broader architectural or runtime assessment. |
| LLM09 Vector and Embedding Weaknesses | VEC001, VEC004 | Covers missing query-time tenant filters and ingestion without tenant metadata. Embedding inversion, retrieval jamming, membership inference, and semantic-cache attacks remain gaps. |
| LLM10 Improper Output Handling | AI005, AI012, MCP003 | Covers model output reaching code, shell, SQL, HTML, parsed-object, and privileged-context sinks. Terminal control characters and automatic external-resource rendering remain gaps. |

## Precision Policy

New coverage is not promoted to `proven` or `likely` from a category keyword alone. It must have an import-resolved sink, traced dataflow, or comparably strong structural fact, remain clean on the safe corpus, and pass the reviewed real-repository regression gate. Plausible but unproven checks belong at `heuristic` evidence and stay hidden unless `--paranoid` is enabled.

The OWASP document is licensed CC BY-SA 4.0. This coverage assessment is original project documentation; category names and identifiers are attributed to the OWASP GenAI Security Project through the official source linked above.