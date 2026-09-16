/**
 * GENERATED FILE — do not edit by hand.
 * Regenerate with: node scripts/sync-advisories.js
 *
 * Snapshot of HIGH/CRITICAL OSV advisories for the LLM/MCP/RAG package
 * watchlist in that script. Bundled so DEP003 stays fully offline at scan
 * time. Only advisories with a machine-comparable exact version range are
 * included — an advisory whose range can't be parsed is dropped rather than
 * shipped as an always-on finding.
 *
 * Synced: 2026-08-04
 */
import type { PackageAdvisory } from "./advisories.js";

export const GENERATED_ADVISORIES: PackageAdvisory[] = [
  {
    "ecosystem": "npm",
    "name": "@langchain/core",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <1.1.8",
      "<0.3.80"
    ],
    "affectedVersions": ">=1.0.0 <1.1.8 || <0.3.80",
    "reason": "CVE-2025-68665: LangChain serialization injection vulnerability enables secret extraction",
    "reference": "https://osv.dev/vulnerability/GHSA-r399-636x-v7f6"
  },
  {
    "ecosystem": "npm",
    "name": "@modelcontextprotocol/inspector",
    "kind": "vulnerable",
    "ranges": [
      "<0.14.1"
    ],
    "affectedVersions": "<0.14.1",
    "reason": "CVE-2025-49596: MCP Inspector proxy server lacks authentication between the Inspector client and proxy",
    "reference": "https://osv.dev/vulnerability/GHSA-7f8r-222p-6f5g"
  },
  {
    "ecosystem": "npm",
    "name": "@modelcontextprotocol/inspector",
    "kind": "vulnerable",
    "ranges": [
      "<0.16.6"
    ],
    "affectedVersions": "<0.16.6",
    "reason": "CVE-2025-58444: MCP Inspector is Vulnerable to Potential Command Execution via XSS When Connecting to an Untrusted MCP Server",
    "reference": "https://osv.dev/vulnerability/GHSA-g9hg-qhmf-q45m"
  },
  {
    "ecosystem": "npm",
    "name": "@modelcontextprotocol/sdk",
    "kind": "vulnerable",
    "ranges": [
      "<1.24.0"
    ],
    "affectedVersions": "<1.24.0",
    "reason": "CVE-2025-66414: Model Context Protocol (MCP) TypeScript SDK does not enable DNS rebinding protection by default",
    "reference": "https://osv.dev/vulnerability/GHSA-w48q-cv73-mx4w"
  },
  {
    "ecosystem": "npm",
    "name": "@modelcontextprotocol/sdk",
    "kind": "vulnerable",
    "ranges": [
      ">=1.3.0 <1.25.2"
    ],
    "affectedVersions": ">=1.3.0 <1.25.2",
    "reason": "CVE-2026-0621: Anthropic's MCP TypeScript SDK has a ReDoS vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-8r9q-7v3j-jr4g"
  },
  {
    "ecosystem": "npm",
    "name": "@modelcontextprotocol/sdk",
    "kind": "vulnerable",
    "ranges": [
      ">=1.10.0 <1.26.0"
    ],
    "affectedVersions": ">=1.10.0 <1.26.0",
    "reason": "CVE-2026-25536: @modelcontextprotocol/sdk has cross-client data leak via shared server/transport instance reuse",
    "reference": "https://osv.dev/vulnerability/GHSA-345p-7cg4-v4c7"
  },
  {
    "ecosystem": "npm",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <1.2.3",
      "<0.3.37"
    ],
    "affectedVersions": ">=1.0.0 <1.2.3 || <0.3.37",
    "reason": "CVE-2025-68665: LangChain serialization injection vulnerability enables secret extraction",
    "reference": "https://osv.dev/vulnerability/GHSA-r399-636x-v7f6"
  },
  {
    "ecosystem": "npm",
    "name": "mcp-remote",
    "kind": "vulnerable",
    "ranges": [
      ">=0.0.5 <0.1.16"
    ],
    "affectedVersions": ">=0.0.5 <0.1.16",
    "reason": "CVE-2025-6514: mcp-remote exposed to OS command injection via untrusted MCP server connections",
    "reference": "https://osv.dev/vulnerability/GHSA-6xpm-ggf7-wc3p"
  },
  {
    "ecosystem": "pypi",
    "name": "chromadb",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <=1.5.9"
    ],
    "affectedVersions": ">=1.0.0 <=1.5.9",
    "reason": "CVE-2026-45829: ChromaDB Python project has a pre-authentication code injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-f4j7-r4q5-qw2c"
  },
  {
    "ecosystem": "pypi",
    "name": "fastmcp",
    "kind": "vulnerable",
    "ranges": [
      "<2.14.2"
    ],
    "affectedVersions": "<2.14.2",
    "reason": "CVE-2025-69196: FastMCP OAuth Proxy token reuse across MCP servers",
    "reference": "https://osv.dev/vulnerability/GHSA-5h2m-4q8j-pqpj"
  },
  {
    "ecosystem": "pypi",
    "name": "fastmcp",
    "kind": "vulnerable",
    "ranges": [
      "<3.2.0"
    ],
    "affectedVersions": "<3.2.0",
    "reason": "CVE-2026-27124: FastMCP: Missing Consent Verification in OAuth Proxy Callback Facilitates Confused Deputy Vulnerabilities",
    "reference": "https://osv.dev/vulnerability/GHSA-rww4-4w9c-7733"
  },
  {
    "ecosystem": "pypi",
    "name": "fastmcp",
    "kind": "vulnerable",
    "ranges": [
      "<3.2.0"
    ],
    "affectedVersions": "<3.2.0",
    "reason": "CVE-2026-32871: FastMCP OpenAPI Provider has an SSRF & Path Traversal Vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-vv7q-7jx5-f767"
  },
  {
    "ecosystem": "pypi",
    "name": "fastmcp",
    "kind": "vulnerable",
    "ranges": [
      "<2.13.0"
    ],
    "affectedVersions": "<2.13.0",
    "reason": "GHSA-c2jp-c369-7pvx: FastMCP Auth Integration Allows for Confused Deputy Account Takeover",
    "reference": "https://osv.dev/vulnerability/GHSA-c2jp-c369-7pvx"
  },
  {
    "ecosystem": "pypi",
    "name": "fastmcp",
    "kind": "vulnerable",
    "ranges": [
      "<2.14.0"
    ],
    "affectedVersions": "<2.14.0",
    "reason": "GHSA-rcfx-77hg-w2wv: FastMCP updated to MCP 1.23+ due to CVE-2025-66416",
    "reference": "https://osv.dev/vulnerability/GHSA-rcfx-77hg-w2wv"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<2.5.0"
    ],
    "affectedVersions": "<2.5.0",
    "reason": "CVE-2021-43831: Files on the host computer can be accessed from the Gradio interface",
    "reference": "https://osv.dev/vulnerability/GHSA-rhq2-3vr9-6mcr"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<2.8.11"
    ],
    "affectedVersions": "<2.8.11",
    "reason": "CVE-2022-24770: Improper Neutralization of Formula Elements in a CSV File in Gradio Flagging",
    "reference": "https://osv.dev/vulnerability/GHSA-f8xq-q7px-wg8c"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.11.0"
    ],
    "affectedVersions": "<4.11.0",
    "reason": "CVE-2023-51449: Gradio makes the `/file` secure against file traversal and server-side request forgery attacks",
    "reference": "https://osv.dev/vulnerability/GHSA-6qm2-wpxq-7qh2"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.14.0"
    ],
    "affectedVersions": "<4.14.0",
    "reason": "CVE-2023-6572: Gradio Exposure of Sensitive Information to an Unauthorized Actor vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-gqvf-3hgp-5hxv"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.9.0"
    ],
    "affectedVersions": "<4.9.0",
    "reason": "CVE-2024-0964: Gradio Path Traversal vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-f3h9-8phc-6gvh"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.13.0"
    ],
    "affectedVersions": "<4.13.0",
    "reason": "CVE-2024-1561: gradio vulnerable to Path Traversal",
    "reference": "https://osv.dev/vulnerability/GHSA-g9cj-cfpp-4g2x"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.19.2"
    ],
    "affectedVersions": "<4.19.2",
    "reason": "CVE-2024-1728: Gradio allows users to access arbitrary files",
    "reference": "https://osv.dev/vulnerability/GHSA-m842-4qm8-7gpq"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.18.0"
    ],
    "affectedVersions": "<4.18.0",
    "reason": "CVE-2024-2206: gradio Server-Side Request Forgery vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-r364-m2j9-mf4h"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.20.0"
    ],
    "affectedVersions": "<4.20.0",
    "reason": "CVE-2024-34510: Gradio allows credential leakage on Windows",
    "reference": "https://osv.dev/vulnerability/GHSA-rvfh-h6c7-fc3c"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<=4.36.0"
    ],
    "affectedVersions": "<=4.36.0",
    "reason": "CVE-2024-4325: Server-Side Request Forgery in gradio",
    "reference": "https://osv.dev/vulnerability/GHSA-973g-55hp-3frw"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.44.0"
    ],
    "affectedVersions": "<4.44.0",
    "reason": "CVE-2024-47084: Gradios's CORS origin validation is not performed when the request has a cookie",
    "reference": "https://osv.dev/vulnerability/GHSA-3c67-5hwx-f6wx"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<5.0.0"
    ],
    "affectedVersions": "<5.0.0",
    "reason": "CVE-2024-47867: Gradio lacks integrity checking on the downloaded FRP client",
    "reference": "https://osv.dev/vulnerability/GHSA-8c87-gvhj-xm8m"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<5.0.0"
    ],
    "affectedVersions": "<5.0.0",
    "reason": "CVE-2024-47870: Gradio has a race condition in update_root_in_config may redirect user traffic",
    "reference": "https://osv.dev/vulnerability/GHSA-xh2x-3mrm-fwqm"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<5.0.0"
    ],
    "affectedVersions": "<5.0.0",
    "reason": "CVE-2024-47871: Gradio uses insecure communication between the FRP client and server",
    "reference": "https://osv.dev/vulnerability/GHSA-279j-x4gx-hfrh"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<4.31.3"
    ],
    "affectedVersions": "<4.31.3",
    "reason": "CVE-2024-4941: Local file inclusion in gradio",
    "reference": "https://osv.dev/vulnerability/GHSA-6v6g-j5fq-hpvw"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<=5.22.0"
    ],
    "affectedVersions": "<=5.22.0",
    "reason": "CVE-2024-8966: Gradio DOS in multipart boundry while uploading the file",
    "reference": "https://osv.dev/vulnerability/GHSA-5cpq-9538-jm2j"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<5.11.0"
    ],
    "affectedVersions": "<5.11.0",
    "reason": "CVE-2025-23042: Gradio Blocked Path ACL Bypass Vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-j2jg-fq62-7c3h"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<6.7.0"
    ],
    "affectedVersions": "<6.7.0",
    "reason": "CVE-2026-28414: Gradio is Vulnerable to Absolute Path Traversal on Windows with Python 3.13+",
    "reference": "https://osv.dev/vulnerability/GHSA-39mp-8hj3-5c49"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<6.6.0"
    ],
    "affectedVersions": "<6.6.0",
    "reason": "CVE-2026-28416: Gradio has SSRF via Malicious `proxy_url` Injection in `gr.load()` Config Processing",
    "reference": "https://osv.dev/vulnerability/GHSA-jmh7-g254-2cq9"
  },
  {
    "ecosystem": "pypi",
    "name": "gradio",
    "kind": "vulnerable",
    "ranges": [
      "<6.15.0"
    ],
    "affectedVersions": "<6.15.0",
    "reason": "CVE-2026-48545: Gradio contains a cookie injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-7hp7-4p35-3cx2"
  },
  {
    "ecosystem": "pypi",
    "name": "haystack-ai",
    "kind": "vulnerable",
    "ranges": [
      "<2.3.1"
    ],
    "affectedVersions": "<2.3.1",
    "reason": "CVE-2024-41950: Insecure Jinja2 templates rendered in Haystack Components can lead to RCE",
    "reference": "https://osv.dev/vulnerability/GHSA-hx9v-6r9f-w677"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<=0.0.131"
    ],
    "affectedVersions": "<=0.0.131",
    "reason": "CVE-2023-29374: LangChain vulnerable to code injection",
    "reference": "https://osv.dev/vulnerability/GHSA-fprp-p869-w6q2"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.247"
    ],
    "affectedVersions": "<0.0.247",
    "reason": "CVE-2023-32785: Langchain SQL Injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-8h5w-f6q9-wg35"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.329"
    ],
    "affectedVersions": "<0.0.329",
    "reason": "CVE-2023-32786: Langchain Server-Side Request Forgery vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-6h8p-4hx9-w66c"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.225"
    ],
    "affectedVersions": "<0.0.225",
    "reason": "CVE-2023-34540: Langchain OS Command Injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-x32c-59v5-h7fg"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.247"
    ],
    "affectedVersions": "<0.0.247",
    "reason": "CVE-2023-34541: Langchain vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-6643-h7h5-x9wh"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.236"
    ],
    "affectedVersions": "<0.0.236",
    "reason": "CVE-2023-36095: langchain Code Injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-gwqq-6vq7-5j86"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.247"
    ],
    "affectedVersions": "<0.0.247",
    "reason": "CVE-2023-36188: langchain vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-57fc-8q82-gfp3"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.247"
    ],
    "affectedVersions": "<0.0.247",
    "reason": "CVE-2023-36189: langchain SQL Injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-7q94-qpjr-xpgm"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.247"
    ],
    "affectedVersions": "<0.0.247",
    "reason": "CVE-2023-36258: langchain arbitrary code execution vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-2qmj-7962-cjq8"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.312"
    ],
    "affectedVersions": "<0.0.312",
    "reason": "CVE-2023-36281: langchain vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-7gfq-f96f-g85j"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.247"
    ],
    "affectedVersions": "<0.0.247",
    "reason": "CVE-2023-38860: LangChain vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-fj32-q626-pjjc"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.236"
    ],
    "affectedVersions": "<0.0.236",
    "reason": "CVE-2023-38896: LangChain vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-92j5-3459-qgp4"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.308"
    ],
    "affectedVersions": "<0.0.308",
    "reason": "CVE-2023-39631: Langchain vulnerable to arbitrary code execution via the evaluate function in the numexpr library",
    "reference": "https://osv.dev/vulnerability/GHSA-f73w-4m7g-ch9x"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.325"
    ],
    "affectedVersions": "<0.0.325",
    "reason": "CVE-2023-39659: LangChain vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-prgp-w7vf-ch62"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.317"
    ],
    "affectedVersions": "<0.0.317",
    "reason": "CVE-2023-46229: LangChain Server Side Request Forgery vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-655w-fm8m-m478"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain",
    "kind": "vulnerable",
    "ranges": [
      "<0.3.30"
    ],
    "affectedVersions": "<0.3.30",
    "reason": "CVE-2026-45134: LangSmith SDK: Public prompt pull deserializes untrusted manifests without trust boundary warning",
    "reference": "https://osv.dev/vulnerability/GHSA-3644-q5cj-c5c7"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-community",
    "kind": "vulnerable",
    "ranges": [
      "<0.2.4"
    ],
    "affectedVersions": "<0.2.4",
    "reason": "CVE-2024-5998: LangChain pickle deserialization of untrusted data",
    "reference": "https://osv.dev/vulnerability/GHSA-f2jm-rw3h-6phg"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-community",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.28"
    ],
    "affectedVersions": "<0.0.28",
    "reason": "CVE-2025-2828: LangChain Community SSRF vulnerability exists in RequestsToolkit component",
    "reference": "https://osv.dev/vulnerability/GHSA-h5gc-rm8j-5gpr"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-community",
    "kind": "vulnerable",
    "ranges": [
      "<0.3.27"
    ],
    "affectedVersions": "<0.3.27",
    "reason": "CVE-2025-6984: Langchain Community Vulnerable to XML External Entity (XXE) Attacks",
    "reference": "https://osv.dev/vulnerability/GHSA-pc6w-59fv-rh23"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-core",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <1.0.7",
      "<0.3.80"
    ],
    "affectedVersions": ">=1.0.0 <1.0.7 || <0.3.80",
    "reason": "CVE-2025-65106: LangChain Vulnerable to Template Injection via Attribute Access in Prompt Templates",
    "reference": "https://osv.dev/vulnerability/GHSA-6qv9-48xg-fc7f"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-core",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <1.2.5",
      "<0.3.81"
    ],
    "affectedVersions": ">=1.0.0 <1.2.5 || <0.3.81",
    "reason": "CVE-2025-68664: LangChain serialization injection vulnerability enables secret extraction in dumps/loads APIs",
    "reference": "https://osv.dev/vulnerability/GHSA-c67j-w6g6-q2cm"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-core",
    "kind": "vulnerable",
    "ranges": [
      "<1.2.22"
    ],
    "affectedVersions": "<1.2.22",
    "reason": "CVE-2026-34070: LangChain Core has Path Traversal vulnerabilites in legacy `load_prompt` functions",
    "reference": "https://osv.dev/vulnerability/GHSA-qh6h-p6c9-ff54"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-core",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <1.3.3",
      "<0.3.85"
    ],
    "affectedVersions": ">=1.0.0 <1.3.3 || <0.3.85",
    "reason": "CVE-2026-44843: LangChain vulnerable to unsafe deserialization of attacker-controlled objects through overly broad `load()` allowlists",
    "reference": "https://osv.dev/vulnerability/GHSA-pjwx-r37v-7724"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-experimental",
    "kind": "vulnerable",
    "ranges": [
      "<=0.0.14"
    ],
    "affectedVersions": "<=0.0.14",
    "reason": "CVE-2023-44467: langchain_experimental vulnerable to arbitrary code execution via PALChain in the python exec method",
    "reference": "https://osv.dev/vulnerability/GHSA-gjjr-63x4-v8cq"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-experimental",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.21"
    ],
    "affectedVersions": "<0.0.21",
    "reason": "CVE-2024-21513: langchain-experimental vulnerable to Arbitrary Code Execution",
    "reference": "https://osv.dev/vulnerability/GHSA-cgcg-p68q-3w7v"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-experimental",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.52"
    ],
    "affectedVersions": "<0.0.52",
    "reason": "CVE-2024-27444: LangChain Experimental vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-v8vj-cv27-hjv8"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-experimental",
    "kind": "vulnerable",
    "ranges": [
      "<0.0.61"
    ],
    "affectedVersions": "<0.0.61",
    "reason": "CVE-2024-38459: langchain_experimental Code Execution via Python REPL access",
    "reference": "https://osv.dev/vulnerability/GHSA-wmvm-9vqv-5qpp"
  },
  {
    "ecosystem": "pypi",
    "name": "langchain-experimental",
    "kind": "vulnerable",
    "ranges": [
      ">=0.1.17 <=0.3.0"
    ],
    "affectedVersions": ">=0.1.17 <=0.3.0",
    "reason": "CVE-2024-46946: LangChain Experimental Eval Injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-p2qj-r53j-h3xj"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.0.15"
    ],
    "affectedVersions": "<1.0.15",
    "reason": "CVE-2024-37014: Langflow remote code execution vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-qg33-x2c5-6p44"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<=1.0.12"
    ],
    "affectedVersions": "<=1.0.12",
    "reason": "CVE-2024-42835: langflow has vulnerability in PythonCodeTool component",
    "reference": "https://osv.dev/vulnerability/GHSA-56m6-4mhw-h3g5"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.3.0"
    ],
    "affectedVersions": "<1.3.0",
    "reason": "CVE-2025-3248: Langflow Unauth RCE",
    "reference": "https://osv.dev/vulnerability/GHSA-rvqx-wpfh-mfx7"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.7.0"
    ],
    "affectedVersions": "<1.7.0",
    "reason": "CVE-2025-34291: Langflow CORS misconfiguration enables Account Takeover and RCE",
    "reference": "https://osv.dev/vulnerability/GHSA-577h-p2hh-v4mv"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.5.1"
    ],
    "affectedVersions": "<1.5.1",
    "reason": "CVE-2025-57760: Langflow Vulnerable to Privilege Escalation via CLI Superuser Creation (Post-RCE)",
    "reference": "https://osv.dev/vulnerability/GHSA-4gv9-mp8m-592r"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.7.1"
    ],
    "affectedVersions": "<1.7.1",
    "reason": "CVE-2025-68477: Langflow vulnerable to Server-Side Request Forgery",
    "reference": "https://osv.dev/vulnerability/GHSA-5993-7p27-66g5"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.7.1"
    ],
    "affectedVersions": "<1.7.1",
    "reason": "CVE-2025-68478: External Control of File Name or Path in Langflow",
    "reference": "https://osv.dev/vulnerability/GHSA-f43r-cc68-gpx4"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<=1.7.3"
    ],
    "affectedVersions": "<=1.7.3",
    "reason": "CVE-2026-0770: Langflow affected by Remote Code Execution via validate_code() exec()",
    "reference": "https://osv.dev/vulnerability/GHSA-g22f-v6f7-2hrh"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.7.1"
    ],
    "affectedVersions": "<1.7.1",
    "reason": "CVE-2026-21445: Langflow Missing Authentication on Critical API Endpoints",
    "reference": "https://osv.dev/vulnerability/GHSA-c5cp-vx83-jhqx"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.0"
    ],
    "affectedVersions": "<1.9.0",
    "reason": "CVE-2026-33017: Unauthenticated Remote Code Execution in Langflow via Public Flow Build Endpoint",
    "reference": "https://osv.dev/vulnerability/GHSA-vwmf-pq79-vjvx"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.0"
    ],
    "affectedVersions": "<1.9.0",
    "reason": "CVE-2026-33053: Langflow is Missing Ownership Verification in API Key Deletion (IDOR)",
    "reference": "https://osv.dev/vulnerability/GHSA-rf6x-r45m-xv3w"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      ">=1.2.0 <1.9.0"
    ],
    "affectedVersions": ">=1.2.0 <1.9.0",
    "reason": "CVE-2026-33309: Langflow has an Arbitrary File Write (RCE) via v2 API",
    "reference": "https://osv.dev/vulnerability/GHSA-g2j9-7rj2-gm6c"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      ">=1.0.0 <1.9.0"
    ],
    "affectedVersions": ">=1.0.0 <1.9.0",
    "reason": "CVE-2026-33484: langflow has Unauthenticated IDOR on Image Downloads",
    "reference": "https://osv.dev/vulnerability/GHSA-7grx-3xcx-2xv5"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.7.1"
    ],
    "affectedVersions": "<1.7.1",
    "reason": "CVE-2026-33497: langflow: /profile_pictures/{folder_name}/{file_name} endpoint file reading",
    "reference": "https://osv.dev/vulnerability/GHSA-ph9w-r52h-28p7"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.0"
    ],
    "affectedVersions": "<1.9.0",
    "reason": "CVE-2026-33760: Langflow: IDOR/BOLA in Monitor API — Missing Ownership Enforcement on 7 Endpoints",
    "reference": "https://osv.dev/vulnerability/GHSA-9c59-2mvc-vfr8"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.0"
    ],
    "affectedVersions": "<1.9.0",
    "reason": "CVE-2026-33873: Langflow has Authenticated Code Execution in Agentic Assistant Validation",
    "reference": "https://osv.dev/vulnerability/GHSA-v8hw-mh8c-jxfc"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.5.1"
    ],
    "affectedVersions": "<1.5.1",
    "reason": "CVE-2026-34046: Langflow: Authenticated Users Can Read, Modify, and Delete Any Flow via Missing Ownership Check",
    "reference": "https://osv.dev/vulnerability/GHSA-8c4j-f57c-35cf"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.0"
    ],
    "affectedVersions": "<1.9.0",
    "reason": "CVE-2026-42048: Langflow Knowledge Bases API is Vulnerable to Path Traversal",
    "reference": "https://osv.dev/vulnerability/GHSA-9whx-c884-c68q"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.2"
    ],
    "affectedVersions": "<1.9.2",
    "reason": "CVE-2026-48519: Langflow: Unauthenticated RCE in Shareable Playgrounds",
    "reference": "https://osv.dev/vulnerability/GHSA-v5ff-9q35-q26f"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.1"
    ],
    "affectedVersions": "<1.9.1",
    "reason": "CVE-2026-55255: Langflow: IDOR Vulnerability in `/api/v1/responses` Endpoint Allows Authenticated Attackers to Access Another User's Flow",
    "reference": "https://osv.dev/vulnerability/GHSA-qrpv-q767-xqq2"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.0.19"
    ],
    "affectedVersions": "<1.0.19",
    "reason": "CVE-2026-55446: Langflow: Unauthenticated DoS through multipart form boundary file upload",
    "reference": "https://osv.dev/vulnerability/GHSA-qwqc-p3q8-wcg9"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.2"
    ],
    "affectedVersions": "<1.9.2",
    "reason": "CVE-2026-55447: Langflow: BaseFileComponent-based nodes arbitrary file read with RCE exploit",
    "reference": "https://osv.dev/vulnerability/GHSA-ccv6-r384-xp75"
  },
  {
    "ecosystem": "pypi",
    "name": "langflow",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.1"
    ],
    "affectedVersions": "<1.9.1",
    "reason": "CVE-2026-55450: Langflow: Unauthenticated file upload leads to DoS (space exhaustion) and information leak",
    "reference": "https://osv.dev/vulnerability/GHSA-x223-p2gf-v735"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.34.42"
    ],
    "affectedVersions": "<1.34.42",
    "reason": "CVE-2024-2952: LiteLLM has Server-Side Template Injection vulnerability in /completions endpoint",
    "reference": "https://osv.dev/vulnerability/GHSA-46cm-pfwv-cgf8"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<=1.28.11"
    ],
    "affectedVersions": "<=1.28.11",
    "reason": "CVE-2024-4264: litellm passes untrusted data to `eval` function without sanitization",
    "reference": "https://osv.dev/vulnerability/GHSA-7ggm-4rjg-594w"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.35.36"
    ],
    "affectedVersions": "<1.35.36",
    "reason": "CVE-2024-4888: Arbitrary file deletion in litellm",
    "reference": "https://osv.dev/vulnerability/GHSA-3xr8-qfvj-9p9j"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.40.16"
    ],
    "affectedVersions": "<1.40.16",
    "reason": "CVE-2024-5751: litellm vulnerable to remote code execution based on using eval unsafely",
    "reference": "https://osv.dev/vulnerability/GHSA-gppg-gqw8-wh9g"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.44.8"
    ],
    "affectedVersions": "<1.44.8",
    "reason": "CVE-2024-6587: LiteLLM Server-Side Request Forgery (SSRF) vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-g26j-5385-hhw3"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.56.2"
    ],
    "affectedVersions": "<1.56.2",
    "reason": "CVE-2024-8984: LiteLLM Vulnerable to Denial of Service (DoS) via Crafted HTTP Request",
    "reference": "https://osv.dev/vulnerability/GHSA-fh2c-86xm-pm2x"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.44.12"
    ],
    "affectedVersions": "<1.44.12",
    "reason": "CVE-2024-9606: LiteLLM Reveals Portion of API Key via a Logging File",
    "reference": "https://osv.dev/vulnerability/GHSA-g5pg-73fc-hjwq"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<=1.52.1"
    ],
    "affectedVersions": "<=1.52.1",
    "reason": "CVE-2025-0330: LiteLLM Has a Leakage of Langfuse API Keys",
    "reference": "https://osv.dev/vulnerability/GHSA-879v-fggm-vxw2"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.61.15"
    ],
    "affectedVersions": "<1.61.15",
    "reason": "CVE-2025-0628: LiteLLM Has an Improper Authorization Vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-fjcf-3j3r-78rp"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.83.0"
    ],
    "affectedVersions": "<1.83.0",
    "reason": "CVE-2026-35029: LiteLLM: Privilege escalation via unrestricted proxy configuration endpoint",
    "reference": "https://osv.dev/vulnerability/GHSA-53mr-6c8q-9789"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.83.0"
    ],
    "affectedVersions": "<1.83.0",
    "reason": "CVE-2026-35030: LiteLLM: Authentication bypass via OIDC userinfo cache key collision",
    "reference": "https://osv.dev/vulnerability/GHSA-jjhc-v7c2-5hh6"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      ">=1.81.8 <1.83.10"
    ],
    "affectedVersions": ">=1.81.8 <1.83.10",
    "reason": "CVE-2026-40217: LiteLLM has a sandbox escape in custom-code guardrail",
    "reference": "https://osv.dev/vulnerability/GHSA-wxxx-gvqv-xp7p"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      ">=1.80.5 <1.83.7"
    ],
    "affectedVersions": ">=1.80.5 <1.83.7",
    "reason": "CVE-2026-42203: LiteLLM: Server-Side Template Injection in /prompts/test endpoint",
    "reference": "https://osv.dev/vulnerability/GHSA-xqmj-j6mv-4862"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      ">=1.81.16 <1.83.7"
    ],
    "affectedVersions": ">=1.81.16 <1.83.7",
    "reason": "CVE-2026-42208: LiteLLM has SQL Injection in Proxy API key verification",
    "reference": "https://osv.dev/vulnerability/GHSA-r75f-5x8p-qvmc"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      ">=1.74.2 <1.83.7"
    ],
    "affectedVersions": ">=1.74.2 <1.83.7",
    "reason": "CVE-2026-42271: LiteLLM: Authenticated command execution via MCP stdio test endpoints",
    "reference": "https://osv.dev/vulnerability/GHSA-v4p8-mg3p-g94g"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.83.14"
    ],
    "affectedVersions": "<1.83.14",
    "reason": "CVE-2026-47101: LiteLLM allows an authenticated internal_user to create API keys with access to routes that their role does not permit",
    "reference": "https://osv.dev/vulnerability/GHSA-qrc4-49gv-mv9m"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.83.10"
    ],
    "affectedVersions": "<1.83.10",
    "reason": "CVE-2026-47102: LiteLLM allows a user to modify their own user_role via the /user/update endpoint",
    "reference": "https://osv.dev/vulnerability/GHSA-wpfp-gwwc-vwq6"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.84.0"
    ],
    "affectedVersions": "<1.84.0",
    "reason": "CVE-2026-49468: LiteLLM: Authentication Bypass via Host Header Injection",
    "reference": "https://osv.dev/vulnerability/GHSA-4xpc-pv4p-pm3w"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.84.0"
    ],
    "affectedVersions": "<1.84.0",
    "reason": "CVE-2026-59822: LiteLLM: MCP Authentication Bypass via OAuth2 Passthrough Fallback",
    "reference": "https://osv.dev/vulnerability/GHSA-7488-6r32-c95q"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      ">=1.82.7 <=1.82.8"
    ],
    "affectedVersions": ">=1.82.7 <=1.82.8",
    "reason": "GHSA-5mg7-485q-xm76: Two LiteLLM versions published containing credential harvesting malware",
    "reference": "https://osv.dev/vulnerability/GHSA-5mg7-485q-xm76"
  },
  {
    "ecosystem": "pypi",
    "name": "litellm",
    "kind": "vulnerable",
    "ranges": [
      "<1.83.0"
    ],
    "affectedVersions": "<1.83.0",
    "reason": "GHSA-69x8-hrgq-fjj8: LiteLLM: Password hash exposure and pass-the-hash authentication bypass",
    "reference": "https://osv.dev/vulnerability/GHSA-69x8-hrgq-fjj8"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-cpp-python",
    "kind": "vulnerable",
    "ranges": [
      ">=0.2.30 <0.2.72"
    ],
    "affectedVersions": ">=0.2.30 <0.2.72",
    "reason": "CVE-2024-34359: llama-cpp-python vulnerable to Remote Code Execution by Server-Side Template Injection in Model Metadata",
    "reference": "https://osv.dev/vulnerability/GHSA-56xg-wfcc-g829"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      "<0.9.14"
    ],
    "affectedVersions": "<0.9.14",
    "reason": "CVE-2023-39662: llama-index vulnerable to arbitrary code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-2xxc-73fv-36f7"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      "<0.12.3"
    ],
    "affectedVersions": "<0.12.3",
    "reason": "CVE-2024-12911: LlamaIndex vulnerable to Creation of Temporary File in Directory with Insecure Permissions",
    "reference": "https://osv.dev/vulnerability/GHSA-jmgm-gx32-vp4w"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      "<=0.9.35"
    ],
    "affectedVersions": "<=0.9.35",
    "reason": "CVE-2024-23751: SQL injection in llama-index",
    "reference": "https://osv.dev/vulnerability/GHSA-2jxw-4hm4-6w87"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      "<0.10.13"
    ],
    "affectedVersions": "<0.10.13",
    "reason": "CVE-2024-4181: RunGptLLM class in LlamaIndex has a command injection",
    "reference": "https://osv.dev/vulnerability/GHSA-pw38-xv9x-h8ch"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      ">=0.12.15 <0.12.21"
    ],
    "affectedVersions": ">=0.12.15 <0.12.21",
    "reason": "CVE-2025-1752: LlamaIndex Vulnerable to Denial of Service (DoS)",
    "reference": "https://osv.dev/vulnerability/GHSA-7c85-87cp-mr6g"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      "<0.12.28"
    ],
    "affectedVersions": "<0.12.28",
    "reason": "CVE-2025-1793: llama_index vulnerable to SQL Injection",
    "reference": "https://osv.dev/vulnerability/GHSA-v3c8-3pr6-gr7p"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index",
    "kind": "vulnerable",
    "ranges": [
      "<0.13.0"
    ],
    "affectedVersions": "<0.13.0",
    "reason": "CVE-2025-7707: llama-index has Insecure Temporary File",
    "reference": "https://osv.dev/vulnerability/GHSA-rg9h-vx28-xxp5"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      "<0.12.6"
    ],
    "affectedVersions": "<0.12.6",
    "reason": "CVE-2024-12704: LlamaIndex Improper Handling of Exceptional Conditions vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-j3wr-m6xh-64hg"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      "<0.10.24"
    ],
    "affectedVersions": "<0.10.24",
    "reason": "CVE-2024-3098: llama-index-core Prompt Injection vulnerability leading to Arbitrary Code Execution",
    "reference": "https://osv.dev/vulnerability/GHSA-wvpx-g427-q9wc"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      "<0.10.24"
    ],
    "affectedVersions": "<0.10.24",
    "reason": "CVE-2024-3271: llama-index-core Command Injection vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-r6gp-rff2-p3hf"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      "<0.10.38"
    ],
    "affectedVersions": "<0.10.38",
    "reason": "CVE-2024-45201: LlamaIndex includes an exec call for `import {cls_name}`",
    "reference": "https://osv.dev/vulnerability/GHSA-fxc2-8m62-m85x"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      "<0.12.38"
    ],
    "affectedVersions": "<0.12.38",
    "reason": "CVE-2025-5302: LlamaIndex affected by a Denial of Service (DOS) in JSONReader",
    "reference": "https://osv.dev/vulnerability/GHSA-7753-xrfw-ch36"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      ">=0.11.23 <0.12.41"
    ],
    "affectedVersions": ">=0.11.23 <0.12.41",
    "reason": "CVE-2025-6209: LlamaIndex vulnerable to Path Traversal attack through its encode_image function",
    "reference": "https://osv.dev/vulnerability/GHSA-2rhq-96q8-4vjq"
  },
  {
    "ecosystem": "pypi",
    "name": "llama-index-core",
    "kind": "vulnerable",
    "ranges": [
      "<0.13.0"
    ],
    "affectedVersions": "<0.13.0",
    "reason": "CVE-2025-7647: llama-index-core insecurely handles temporary files",
    "reference": "https://osv.dev/vulnerability/GHSA-cr7q-2w66-hjcm"
  },
  {
    "ecosystem": "pypi",
    "name": "mcp",
    "kind": "vulnerable",
    "ranges": [
      "<1.10.0"
    ],
    "affectedVersions": "<1.10.0",
    "reason": "CVE-2025-53365: MCP Python SDK has Unhandled Exception in Streamable HTTP Transport, Leading to Denial of Service",
    "reference": "https://osv.dev/vulnerability/GHSA-j975-95f5-7wqh"
  },
  {
    "ecosystem": "pypi",
    "name": "mcp",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.4"
    ],
    "affectedVersions": "<1.9.4",
    "reason": "CVE-2025-53366: MCP Python SDK vulnerability in the FastMCP Server causes validation error, leading to DoS",
    "reference": "https://osv.dev/vulnerability/GHSA-3qhf-m339-9g5v"
  },
  {
    "ecosystem": "pypi",
    "name": "mcp",
    "kind": "vulnerable",
    "ranges": [
      "<1.23.0"
    ],
    "affectedVersions": "<1.23.0",
    "reason": "CVE-2025-66416: Model Context Protocol (MCP) Python SDK does not enable DNS rebinding protection by default",
    "reference": "https://osv.dev/vulnerability/GHSA-9h52-p55h-vw2f"
  },
  {
    "ecosystem": "pypi",
    "name": "mcp",
    "kind": "vulnerable",
    "ranges": [
      "<1.27.2"
    ],
    "affectedVersions": "<1.27.2",
    "reason": "CVE-2026-52869: MCP Python SDK: HTTP transports serve session requests without verifying the authenticated principal",
    "reference": "https://osv.dev/vulnerability/GHSA-jpw9-pfvf-9f58"
  },
  {
    "ecosystem": "pypi",
    "name": "mcp",
    "kind": "vulnerable",
    "ranges": [
      ">=1.23.0 <1.27.2"
    ],
    "affectedVersions": ">=1.23.0 <1.27.2",
    "reason": "CVE-2026-52870: MCP Python SDK: Experimental task handlers allow any client to access and cancel other clients' tasks",
    "reference": "https://osv.dev/vulnerability/GHSA-hvrp-rf83-w775"
  },
  {
    "ecosystem": "pypi",
    "name": "mcp",
    "kind": "vulnerable",
    "ranges": [
      "<1.28.1"
    ],
    "affectedVersions": "<1.28.1",
    "reason": "CVE-2026-59950: MCP Python SDK: WebSocket server transport does not support Host/Origin validation",
    "reference": "https://osv.dev/vulnerability/GHSA-vj7q-gjh5-988w"
  },
  {
    "ecosystem": "pypi",
    "name": "qdrant-client",
    "kind": "vulnerable",
    "ranges": [
      "<1.9.0"
    ],
    "affectedVersions": "<1.9.0",
    "reason": "CVE-2024-3829: qdrant input validation failure",
    "reference": "https://osv.dev/vulnerability/GHSA-7m75-x27w-r52r"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<4.36.0"
    ],
    "affectedVersions": "<4.36.0",
    "reason": "CVE-2023-6730: transformers has a Deserialization of Untrusted Data vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-3863-2447-669p"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<4.36.0"
    ],
    "affectedVersions": "<4.36.0",
    "reason": "CVE-2023-7018: transformers has a Deserialization of Untrusted Data vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-v68g-wm8c-6x7j"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<4.48.0"
    ],
    "affectedVersions": "<4.48.0",
    "reason": "CVE-2024-11392: Deserialization of Untrusted Data in Hugging Face Transformers",
    "reference": "https://osv.dev/vulnerability/GHSA-qxrp-vhvm-j765"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<4.48.0"
    ],
    "affectedVersions": "<4.48.0",
    "reason": "CVE-2024-11393: Deserialization of Untrusted Data in Hugging Face Transformers",
    "reference": "https://osv.dev/vulnerability/GHSA-wrfc-pvp9-mr9g"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<4.48.0"
    ],
    "affectedVersions": "<4.48.0",
    "reason": "CVE-2024-11394: Deserialization of Untrusted Data in Hugging Face Transformers",
    "reference": "https://osv.dev/vulnerability/GHSA-hxxf-235m-72v3"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<5.3.0"
    ],
    "affectedVersions": "<5.3.0",
    "reason": "CVE-2026-4372: HuggingFace transformers vulnerable to remote code execution",
    "reference": "https://osv.dev/vulnerability/GHSA-29pf-2h5f-8g72"
  },
  {
    "ecosystem": "pypi",
    "name": "transformers",
    "kind": "vulnerable",
    "ranges": [
      "<5.5.0"
    ],
    "affectedVersions": "<5.5.0",
    "reason": "CVE-2026-5241: huggingface/transformers: Arbitrary Code Execution During Model Initialization in the LightGlue Model Loading Path",
    "reference": "https://osv.dev/vulnerability/GHSA-fgcw-684q-jj6r"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<=0.6.2"
    ],
    "affectedVersions": "<=0.6.2",
    "reason": "CVE-2024-11041: vLLM Deserialization of Untrusted Data vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-5vqr-wprc-cpp7"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.5.5"
    ],
    "affectedVersions": "<0.5.5",
    "reason": "CVE-2024-8768: vLLM denial of service vulnerability",
    "reference": "https://osv.dev/vulnerability/GHSA-w2r7-9579-27hf"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<=0.8.1"
    ],
    "affectedVersions": "<=0.8.1",
    "reason": "CVE-2024-9052: vLLM deserialization vulnerability in vllm.distributed.GroupCoordinator.recv_object",
    "reference": "https://osv.dev/vulnerability/GHSA-pgr7-mhp5-fgjp"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<=0.6.0"
    ],
    "affectedVersions": "<=0.6.0",
    "reason": "CVE-2024-9053: vLLM allows Remote Code Execution by Pickle Deserialization via AsyncEngineRPCServer() RPC server entrypoints",
    "reference": "https://osv.dev/vulnerability/GHSA-cj47-qj6g-x7r4"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.7.0"
    ],
    "affectedVersions": "<0.7.0",
    "reason": "CVE-2025-24357: vllm: Malicious model to RCE by torch.load in hf_model_weights_iterator",
    "reference": "https://osv.dev/vulnerability/GHSA-rh4j-5rhw-hr54"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.6.5 <0.8.0"
    ],
    "affectedVersions": ">=0.6.5 <0.8.0",
    "reason": "CVE-2025-29783: vLLM Allows Remote Code Execution via Mooncake Integration",
    "reference": "https://osv.dev/vulnerability/GHSA-x3m8-f7g5-qhm7"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.5.2 <0.10.0"
    ],
    "affectedVersions": ">=0.5.2 <0.10.0",
    "reason": "CVE-2025-30165: Remote Code Execution Vulnerability in vLLM Multi-Node Cluster Configuration",
    "reference": "https://osv.dev/vulnerability/GHSA-9pcc-gvx5-r5wm"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.5.2 <0.8.5"
    ],
    "affectedVersions": ">=0.5.2 <0.8.5",
    "reason": "CVE-2025-30202: Data exposure via ZeroMQ on multi-node vLLM deployment",
    "reference": "https://osv.dev/vulnerability/GHSA-9f8f-2vmf-885j"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.6.5 <0.8.5"
    ],
    "affectedVersions": ">=0.6.5 <0.8.5",
    "reason": "CVE-2025-32444: vLLM Vulnerable to Remote Code Execution via Mooncake Integration",
    "reference": "https://osv.dev/vulnerability/GHSA-hj4w-hm2g-p6w5"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.6.5 <0.8.5"
    ],
    "affectedVersions": ">=0.6.5 <0.8.5",
    "reason": "CVE-2025-47277: vLLM Allows Remote Code Execution via PyNcclPipe Communication Service",
    "reference": "https://osv.dev/vulnerability/GHSA-hjq4-87xh-g4fv"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.11.0"
    ],
    "affectedVersions": "<0.11.0",
    "reason": "CVE-2025-59425: vLLM is vulnerable to timing attack at bearer auth",
    "reference": "https://osv.dev/vulnerability/GHSA-wr9h-g72x-mwhm"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.10.2 <0.11.1"
    ],
    "affectedVersions": ">=0.10.2 <0.11.1",
    "reason": "CVE-2025-62164: vLLM deserialization vulnerability leading to DoS and potential RCE",
    "reference": "https://osv.dev/vulnerability/GHSA-mrw7-hf4f-83pf"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.5.5 <0.11.1"
    ],
    "affectedVersions": ">=0.5.5 <0.11.1",
    "reason": "CVE-2025-62372: vLLM vulnerable to DoS with incorrect shape of multimodal embedding inputs",
    "reference": "https://osv.dev/vulnerability/GHSA-pmqf-x6x8-p7qw"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.5.0 <0.11.0"
    ],
    "affectedVersions": ">=0.5.0 <0.11.0",
    "reason": "CVE-2025-6242: vLLM is vulnerable to Server-Side Request Forgery (SSRF) through `MediaConnector` class",
    "reference": "https://osv.dev/vulnerability/GHSA-3f6c-7fw2-ppm4"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.11.1"
    ],
    "affectedVersions": "<0.11.1",
    "reason": "CVE-2025-66448: vLLM vulnerable to remote code execution via transformers_utils/get_config",
    "reference": "https://osv.dev/vulnerability/GHSA-8fr4-5q9j-m8gm"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.8.3 <0.14.1"
    ],
    "affectedVersions": ">=0.8.3 <0.14.1",
    "reason": "CVE-2026-22778: vLLM has RCE In Video Processing",
    "reference": "https://osv.dev/vulnerability/GHSA-4r2x-xpjr-7cvv"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.10.1 <0.14.0"
    ],
    "affectedVersions": ">=0.10.1 <0.14.0",
    "reason": "CVE-2026-22807: vLLM affected by RCE via auto_map dynamic module loading during model initialization",
    "reference": "https://osv.dev/vulnerability/GHSA-2pc9-4j83-qjmr"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.14.1"
    ],
    "affectedVersions": "<0.14.1",
    "reason": "CVE-2026-24779: vLLM vulnerable to Server-Side Request Forgery (SSRF) through MediaConnector",
    "reference": "https://osv.dev/vulnerability/GHSA-qh4c-xf7m-gxfc"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.10.1 <0.18.0"
    ],
    "affectedVersions": ">=0.10.1 <0.18.0",
    "reason": "CVE-2026-27893: vLLM has Hardcoded Trust Override in Model Files Enables RCE Despite Explicit User Opt-Out",
    "reference": "https://osv.dev/vulnerability/GHSA-7972-pg2x-xr59"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.22.0"
    ],
    "affectedVersions": "<0.22.0",
    "reason": "CVE-2026-41523: vLLM: Security Check Bypass via assert Statement in Activation Function Loading Allows Arbitrary Code Execution",
    "reference": "https://osv.dev/vulnerability/GHSA-q8gq-377p-jq3r"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.3.0 <0.22.0"
    ],
    "affectedVersions": ">=0.3.0 <0.22.0",
    "reason": "CVE-2026-48746: vLLM: OpenAI auth bypass",
    "reference": "https://osv.dev/vulnerability/GHSA-94f4-hr76-p5j6"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.17.1 <0.24.0"
    ],
    "affectedVersions": ">=0.17.1 <0.24.0",
    "reason": "CVE-2026-54234: vLLM has Remote DoS via Invalid Recovered Token Reinjection",
    "reference": "https://osv.dev/vulnerability/GHSA-8wr5-jm2h-8r4f"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.12.0 <0.24.0"
    ],
    "affectedVersions": ">=0.12.0 <0.24.0",
    "reason": "CVE-2026-55514: vLLM denial of service via prompt embeds on M-RoPE models",
    "reference": "https://osv.dev/vulnerability/GHSA-33cg-gxv8-3p8g"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.24.0"
    ],
    "affectedVersions": "<0.24.0",
    "reason": "CVE-2026-55574: vLLM: ReDoS via structured_outputs.regex compiled without timeout in xgrammar and outlines backends",
    "reference": "https://osv.dev/vulnerability/GHSA-rwxx-mrjm-wc2m"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      ">=0.10.2 <0.13.0"
    ],
    "affectedVersions": ">=0.10.2 <0.13.0",
    "reason": "CVE-2026-56340: vLLM introduced enhanced protection for CVE-2025-62164",
    "reference": "https://osv.dev/vulnerability/GHSA-mcmc-2m55-j8jj"
  },
  {
    "ecosystem": "pypi",
    "name": "vllm",
    "kind": "vulnerable",
    "ranges": [
      "<0.8.0"
    ],
    "affectedVersions": "<0.8.0",
    "reason": "GHSA-ggpf-24jw-3fcw: CVE-2025-24357 Malicious model remote code execution fix bypass with PyTorch < 2.6.0",
    "reference": "https://osv.dev/vulnerability/GHSA-ggpf-24jw-3fcw"
  }
];
