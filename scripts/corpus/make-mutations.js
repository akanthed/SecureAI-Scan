#!/usr/bin/env node
/**
 * Regenerates corpus/mutations/<case>/<name>.patch from the pinned checkouts.
 * The patches are the published artefact; this script documents how they were
 * made and lets them be re-derived if a case is re-pinned.
 *
 * Every mutation is a behaviour-preserving refactor of the command-execution
 * helper a case already uses:
 *   alias      rename the helper (or alias it at import) in every file that uses it
 *   wrapper    route every call through a same-file forwarding function
 *   crossfile  route every call through a new helper module in another file
 * Applied to the vulnerable commit they must still fire (recall). Applied to
 * the fix commit, which uses execFile-style helpers with argument arrays, they
 * must stay clean (guard).
 *
 * Usage: node scripts/corpus/make-mutations.js   (after `npm run corpus` has populated .corpus-cache)
 */
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { checkoutAt, root } from "./lib.js";

const cases = JSON.parse(fs.readFileSync(path.join(root, "corpus", "cases.json"), "utf-8")).cases;
const cacheDir = path.join(root, ".corpus-cache");

const VULN_HELPERS = { execAsync: "promisify(exec)", execPromise: "promisify(exec)", execSync: "execSync" };
const FIX_HELPERS = { execFileAsync: "promisify(execFile)", execFilePromise: "promisify(execFile)", execFileSync: "execFileSync" };
const IMPORT_RE = /import[\s\S]*?from\s*['"][^'"]+['"];?/g;

const word = (h) => new RegExp(`(?<![\\w$.])${h}(?![\\w$])`, "g");
const call = (h) => new RegExp(`(?<![\\w$.])${h}\\(`, "g");
const exportsHelper = (text, h) => new RegExp(`export\\s+(const|function|async function)\\s+${h}\\b`).test(text);

function listSources(dir) {
  const out = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!/^(node_modules|\.git|test|tests|__tests__|dist|build)$/.test(e.name)) walk(p);
      } else if (/\.ts$/.test(e.name) && !/\.(test|spec|d)\.ts$/.test(e.name)) out.push(p);
    }
  };
  walk(path.join(dir, "src"));
  return out;
}

const transforms = {
  alias(text, h) {
    if (exportsHelper(text, h) || !word(h).test(text)) return null;
    const imports = [];
    const shielded = text.replace(IMPORT_RE, (m) => {
      imports.push(m);
      return `\u0000IMPORT${imports.length - 1}\u0000`;
    });
    let body = shielded.replace(word(h), `shellRunner_${h}`);
    const importsOut = imports.map((m) => (/\{[^}]*\}/.test(m) ? m.replace(new RegExp(`(?<![\\w$])${h}(?![\\w$])`), `${h} as shellRunner_${h}`) : m));
    body = body.replace(/\u0000IMPORT(\d+)\u0000/g, (_, i) => importsOut[Number(i)]);
    return body === text ? null : body;
  },
  wrapper(text, h) {
    if (!call(h).test(text)) return null;
    const body = text.replace(call(h), `shellWrapper_${h}(`);
    return `${body.replace(/\s*$/, "")}\n\nfunction shellWrapper_${h}(a: any, b?: any, c?: any): any {\n  return ${h}(a, b, c);\n}\n`;
  },
  crossfile(text, h, file, srcRoot) {
    if (!call(h).test(text) || file === path.join(srcRoot, "shell-helper.ts")) return null;
    const rel = path.relative(path.dirname(file), srcRoot).replace(/\\/g, "/") || ".";
    const spec = `${rel.startsWith(".") ? rel : `./${rel}`}/shell-helper.js`;
    const body = text.replace(call(h), `crossFileRun_${h}(`);
    const lines = body.split("\n");
    // Only the file header counts: later `import "x"` lines can sit inside template strings.
    const header = lines.findIndex((l) => /^(export|const|let|var|function|class|interface|type|async|enum|declare)\b/.test(l));
    let last = -1;
    lines.forEach((l, i) => {
      if ((header < 0 || i < header) && (/^import\s/.test(l) || /from\s*['"][^'"]+['"];?\s*$/.test(l))) last = i;
    });
    lines.splice(last + 1, 0, `import { crossFileRun_${h} } from "${spec}";`);
    return lines.join("\n");
  },
};

function helperModule(helpers) {
  // Plain forwarding functions over the real child_process primitive, the way a
  // hand-written utils/shell.ts looks (no parenthesised callees).
  const direct = (i) => i === "execSync" || i === "execFileSync";
  const impl = (h, i) => (direct(i) ? "" : `const ${h}Impl = ${i};\n\n`);
  const callee = (h, i) => (direct(i) ? i : `${h}Impl`);
  return (
    `import { exec, execFile, execSync, execFileSync } from "child_process";\nimport { promisify } from "util";\n\n` +
    helpers
      .map(([h, i]) => `${impl(h, i)}export function crossFileRun_${h}(a: any, b?: any, c?: any): any {\n  return ${callee(h, i)}(a, b, c);\n}\n`)
      .join("\n")
  );
}

function make(checkout, helperMap, kind, outFile) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "secureai-mut-"));
  fs.cpSync(checkout, scratch, { recursive: true });
  const srcRoot = path.join(scratch, "src");
  const used = new Set();
  let changed = 0;
  for (const file of listSources(scratch)) {
    let text = fs.readFileSync(file, "utf-8");
    const original = text;
    for (const h of Object.keys(helperMap)) {
      const next = transforms[kind](text, h, file, srcRoot);
      if (next !== null) {
        text = next;
        used.add(h);
      }
    }
    if (text !== original) {
      fs.writeFileSync(file, text);
      changed += 1;
    }
  }
  if (kind === "crossfile" && used.size > 0) {
    fs.writeFileSync(path.join(srcRoot, "shell-helper.ts"), helperModule([...used].map((h) => [h, helperMap[h]])));
  }
  const git = (...a) => execFileSync("git", a, { cwd: scratch, encoding: "utf-8", maxBuffer: 1 << 26 });
  git("add", "-N", "src");
  const diff = git("diff", "--no-color", "--src-prefix=a/", "--dst-prefix=b/", "--", "src");
  fs.rmSync(scratch, { recursive: true, force: true });
  if (!diff.trim()) return 0;
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  fs.writeFileSync(outFile, diff);
  return changed;
}

const manifestPath = path.join(root, "corpus", "cases.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
for (const c of manifest.cases) {
  const vuln = checkoutAt(c.repo, c.vulnerableSha, cacheDir);
  const fixed = checkoutAt(c.repo, c.fixSha, cacheDir);
  c.mutations = [];
  for (const kind of ["alias", "wrapper", "crossfile"]) {
    for (const side of ["recall", "guard"]) {
      const out = path.join(root, "corpus", "mutations", c.id, `${side}-${kind}.patch`);
      const n = make(side === "recall" ? vuln : fixed, side === "recall" ? VULN_HELPERS : FIX_HELPERS, kind, out);
      console.log(`${c.id} ${side}:${kind} -> ${n} file(s) changed`);
      if (n > 0) c.mutations.push({ name: kind, kind: side, patch: `mutations/${c.id}/${side}-${kind}.patch` });
    }
  }
}
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
