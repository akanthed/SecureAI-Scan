import fs from "node:fs";
import path from "node:path";
import { stripBom } from "../utils/text.js";

/**
 * AI Bill of Materials — an inventory of every AI-related component in the
 * repository: provider SDKs, model identifiers, vector stores, agent
 * frameworks, and MCP servers. Inventory, not judgment: zero heuristic risk
 * scoring, so zero false positives by construction.
 */

export interface BomComponent {
  kind: "llm-sdk" | "model" | "vector-store" | "agent-framework" | "mcp-server" | "embedding";
  name: string;
  detail?: string;
  files: string[];
}

export interface BomResult {
  generatedAt: string;
  rootPath: string;
  components: BomComponent[];
  owaspNote: string;
}

interface PackageMatcher {
  kind: BomComponent["kind"];
  name: string;
  test: (spec: string) => boolean;
}

const PACKAGE_MATCHERS: PackageMatcher[] = [
  { kind: "llm-sdk", name: "OpenAI SDK", test: (s) => s === "openai" },
  { kind: "llm-sdk", name: "Azure OpenAI SDK", test: (s) => s === "@azure/openai" },
  { kind: "llm-sdk", name: "Anthropic SDK", test: (s) => s.startsWith("@anthropic-ai/") },
  { kind: "llm-sdk", name: "Google Gemini SDK", test: (s) => s === "@google/generative-ai" || s === "@google/genai" || s === "google-generativeai" },
  { kind: "llm-sdk", name: "Vercel AI SDK", test: (s) => s === "ai" || s.startsWith("@ai-sdk/") },
  { kind: "llm-sdk", name: "Cohere SDK", test: (s) => s === "cohere-ai" || s === "cohere" },
  { kind: "llm-sdk", name: "Mistral SDK", test: (s) => s === "@mistralai/mistralai" || s === "mistralai" },
  { kind: "llm-sdk", name: "Groq SDK", test: (s) => s === "groq-sdk" || s === "groq" },
  { kind: "llm-sdk", name: "Ollama SDK", test: (s) => s === "ollama" },
  { kind: "llm-sdk", name: "AWS Bedrock SDK", test: (s) => s === "@aws-sdk/client-bedrock-runtime" || s === "boto3" },
  { kind: "agent-framework", name: "LangChain", test: (s) => s === "langchain" || s.startsWith("@langchain/") || s === "langchain-core" || s === "langchain-community" },
  { kind: "agent-framework", name: "LangGraph", test: (s) => s === "@langchain/langgraph" || s === "langgraph" },
  { kind: "agent-framework", name: "LlamaIndex", test: (s) => s === "llamaindex" || s.startsWith("@llamaindex/") || s === "llama-index" || s.startsWith("llama-index-") },
  { kind: "agent-framework", name: "CrewAI", test: (s) => s === "crewai" },
  { kind: "agent-framework", name: "AutoGen", test: (s) => s === "autogen" || s === "pyautogen" || s === "autogen-agentchat" },
  { kind: "agent-framework", name: "OpenAI Agents", test: (s) => s === "@openai/agents" || s === "openai-agents" },
  { kind: "agent-framework", name: "Claude Agent SDK", test: (s) => s === "@anthropic-ai/claude-agent-sdk" },
  { kind: "mcp-server", name: "MCP SDK", test: (s) => s === "@modelcontextprotocol/sdk" || s === "mcp" || s === "fastmcp" },
  { kind: "vector-store", name: "Pinecone", test: (s) => s === "@pinecone-database/pinecone" || s === "pinecone-client" || s === "pinecone" },
  { kind: "vector-store", name: "Chroma", test: (s) => s === "chromadb" },
  { kind: "vector-store", name: "Weaviate", test: (s) => s === "weaviate-ts-client" || s === "weaviate-client" },
  { kind: "vector-store", name: "Qdrant", test: (s) => s === "@qdrant/js-client-rest" || s === "qdrant-client" },
  { kind: "vector-store", name: "Milvus", test: (s) => s === "@zilliz/milvus2-sdk-node" || s === "pymilvus" },
  { kind: "vector-store", name: "pgvector", test: (s) => s === "pgvector" },
  { kind: "vector-store", name: "FAISS", test: (s) => s === "faiss-node" || s === "faiss-cpu" || s === "faiss-gpu" },
];

// Model identifier patterns found in string literals.
const MODEL_PATTERNS: Array<{ re: RegExp; provider: string }> = [
  { re: /\b(gpt-[45][\w.-]*|gpt-3\.5[\w.-]*|o[134](?:-mini|-preview)?|chatgpt-[\w.-]+)\b/g, provider: "OpenAI" },
  { re: /\b(claude-[\w.-]+)\b/g, provider: "Anthropic" },
  { re: /\b(gemini-[\w.-]+)\b/g, provider: "Google" },
  { re: /\b(llama-?[234][\w.-]*)\b/gi, provider: "Meta" },
  { re: /\b(mistral-[\w.-]+|mixtral-[\w.-]+)\b/g, provider: "Mistral" },
  { re: /\b(command-r[\w.-]*)\b/g, provider: "Cohere" },
  { re: /\b(text-embedding-[\w.-]+|embed-[\w.-]+)\b/g, provider: "embedding" },
  { re: /\b(anthropic\.claude-[\w.:-]+|amazon\.titan-[\w.:-]+)\b/g, provider: "AWS Bedrock" },
];

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", ".next", ".venv", "venv",
  "__pycache__", ".mypy_cache", ".tox", "site-packages", "coverage",
]);

const SOURCE_EXTS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py"]);

function walkFiles(rootPath: string): string[] {
  const results: string[] = [];
  function walk(dir: string, depth: number) {
    if (depth > 8) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), depth + 1);
      } else if (entry.isFile() && SOURCE_EXTS.has(path.extname(entry.name))) {
        results.push(path.join(dir, entry.name));
      }
    }
  }
  walk(rootPath, 0);
  return results;
}

const IMPORT_RES = [
  /import\s+[^"']*["']([^"']+)["']/g,
  /require\(\s*["']([^"']+)["']\s*\)/g,
  /^\s*from\s+([\w.]+)\s+import\b/gm,
  /^\s*import\s+([\w.]+)/gm,
];

function normalizePySpec(spec: string): string {
  return spec.split(".")[0].replace(/_/g, "-");
}

// Model identifiers (esp. bare "o1"/"o3"/"o4") are short enough to collide
// with ordinary identifiers (loop vars, coordinates, temp names). Only scan
// inside string literals — where model IDs actually appear in real code —
// rather than the whole file text, to avoid flagging arbitrary source code.
const STRING_LITERAL_RE = /(["'`])((?:\\.|(?!\1)[\s\S])*?)\1/g;

function extractStringLiterals(raw: string): string {
  let out = "";
  STRING_LITERAL_RE.lastIndex = 0;
  for (const m of raw.matchAll(STRING_LITERAL_RE)) {
    out += m[2] + "\n";
  }
  return out;
}

export function generateBom(rootPath: string): BomResult {
  const resolved = path.resolve(rootPath);
  const componentMap = new Map<string, BomComponent>();

  function add(kind: BomComponent["kind"], name: string, file: string, detail?: string) {
    const key = `${kind}|${name}|${detail ?? ""}`;
    const existing = componentMap.get(key);
    if (existing) {
      if (!existing.files.includes(file) && existing.files.length < 10) existing.files.push(file);
    } else {
      componentMap.set(key, { kind, name, detail, files: [file] });
    }
  }

  // 1. Dependency manifests
  for (const manifest of ["package.json"]) {
    const p = path.join(resolved, manifest);
    try {
      const pkg = JSON.parse(stripBom(fs.readFileSync(p, "utf-8"))) as Record<string, unknown>;
      const deps = {
        ...(pkg.dependencies as Record<string, string> | undefined),
        ...(pkg.devDependencies as Record<string, string> | undefined),
      };
      for (const [dep, version] of Object.entries(deps)) {
        for (const m of PACKAGE_MATCHERS) {
          if (m.test(dep)) add(m.kind, m.name, manifest, `${dep}@${version}`);
        }
      }
    } catch {
      /* no manifest */
    }
  }
  for (const manifest of ["requirements.txt", "pyproject.toml"]) {
    const p = path.join(resolved, manifest);
    try {
      const raw = fs.readFileSync(p, "utf-8");
      for (const line of raw.split(/\r?\n/)) {
        const name = line.trim().split(/[=<>~!\[;\s]/)[0].toLowerCase();
        if (!name) continue;
        for (const m of PACKAGE_MATCHERS) {
          if (m.test(name)) add(m.kind, m.name, manifest, line.trim());
        }
      }
    } catch {
      /* no manifest */
    }
  }

  // 2. Source files: imports + model strings
  for (const file of walkFiles(resolved)) {
    let raw: string;
    try {
      raw = fs.readFileSync(file, "utf-8");
    } catch {
      continue;
    }
    const rel = path.relative(resolved, file);
    const isPy = file.endsWith(".py");

    for (const re of IMPORT_RES) {
      re.lastIndex = 0;
      for (const match of raw.matchAll(re)) {
        const spec = isPy ? normalizePySpec(match[1]) : match[1];
        if (spec.startsWith(".") || spec.startsWith("/")) continue;
        for (const m of PACKAGE_MATCHERS) {
          if (m.test(spec)) add(m.kind, m.name, rel);
        }
      }
    }

    const stringLiterals = extractStringLiterals(raw);
    for (const { re, provider } of MODEL_PATTERNS) {
      re.lastIndex = 0;
      for (const match of stringLiterals.matchAll(re)) {
        const model = match[1];
        const kind = provider === "embedding" ? "embedding" : "model";
        add(kind, model, rel, provider === "embedding" ? undefined : provider);
      }
    }
  }

  // 3. MCP server configs
  const mcpConfigNames = [".mcp.json", "mcp.json", "claude_desktop_config.json"];
  function findConfigs(dir: string, depth: number) {
    if (depth > 4) return;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
        findConfigs(full, depth + 1);
      } else if (entry.isFile() && mcpConfigNames.includes(entry.name)) {
        try {
          const parsed = JSON.parse(stripBom(fs.readFileSync(full, "utf-8"))) as Record<string, unknown>;
          const servers =
            (parsed.mcpServers as Record<string, unknown> | undefined) ??
            (parsed.servers as Record<string, unknown> | undefined) ??
            {};
          for (const [name, cfg] of Object.entries(servers)) {
            const c = cfg as Record<string, unknown>;
            const detail =
              typeof c.command === "string"
                ? `${c.command} ${Array.isArray(c.args) ? (c.args as string[]).join(" ") : ""}`.trim()
                : typeof c.url === "string"
                  ? c.url
                  : undefined;
            add("mcp-server", name, path.relative(resolved, full), detail);
          }
        } catch {
          /* unparseable config */
        }
      }
    }
  }
  findConfigs(resolved, 0);

  const kindOrder: BomComponent["kind"][] = ["llm-sdk", "model", "embedding", "agent-framework", "vector-store", "mcp-server"];
  const components = [...componentMap.values()].sort((a, b) => {
    const k = kindOrder.indexOf(a.kind) - kindOrder.indexOf(b.kind);
    return k !== 0 ? k : a.name.localeCompare(b.name);
  });

  return {
    generatedAt: new Date().toISOString(),
    rootPath: resolved,
    components,
    owaspNote:
      "Inventory supports OWASP LLM03 (Supply Chain) review and EU AI Act Art. 11 technical documentation.",
  };
}

const KIND_LABELS: Record<BomComponent["kind"], string> = {
  "llm-sdk": "LLM Provider SDKs",
  model: "Models Referenced",
  embedding: "Embedding Models",
  "agent-framework": "Agent / RAG Frameworks",
  "vector-store": "Vector Stores",
  "mcp-server": "MCP Servers",
};

export function formatBomMarkdown(bom: BomResult): string {
  const lines: string[] = [];
  lines.push("# AI Bill of Materials");
  lines.push("");
  lines.push(`Generated ${bom.generatedAt} by SecureAI-Scan`);
  lines.push("");
  if (bom.components.length === 0) {
    lines.push("No AI components detected.");
    return lines.join("\n");
  }

  const kinds = [...new Set(bom.components.map((c) => c.kind))];
  for (const kind of kinds) {
    lines.push(`## ${KIND_LABELS[kind]}`);
    lines.push("");
    lines.push("| Component | Detail | Where |");
    lines.push("|-----------|--------|-------|");
    for (const c of bom.components.filter((x) => x.kind === kind)) {
      const files = c.files.slice(0, 3).join(", ") + (c.files.length > 3 ? ` (+${c.files.length - 3})` : "");
      lines.push(`| ${c.name} | ${c.detail ?? ""} | ${files} |`);
    }
    lines.push("");
  }

  lines.push(`> ${bom.owaspNote}`);
  lines.push("");
  return lines.join("\n");
}
