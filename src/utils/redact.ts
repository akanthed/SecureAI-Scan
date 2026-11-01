/**
 * Helpers for describing an MCP server in a report without copying credentials
 * out of its config. Config launch lines and URLs routinely carry tokens
 * (`--api-key=sk-...`, `?key=...`, `https://user:pass@host`), and findings flow
 * on to SARIF uploads, HTML reports and shared terminals.
 */

const PACKAGE_RUNNERS = new Set(["npx", "uvx", "pnpx", "bunx"]);

/** Scheme and host only: userinfo, path, query and fragment are dropped. */
export function redactUrl(raw: string): string {
  try {
    const url = new URL(raw);
    return `${url.protocol}//${url.host}`;
  } catch {
    const withoutQuery = raw.split(/[?#]/)[0];
    return withoutQuery.replace(/^([a-z][a-z0-9+.-]*:\/\/)(?:[^/@]*@)?([^/]*).*$/i, "$1$2");
  }
}

/**
 * The launcher and, for package runners, the package it fetches. Every other
 * argument is replaced by an ellipsis, since flags and positional values are
 * where tokens end up.
 */
export function describeLauncher(command: string, args: string[] = []): string {
  if (PACKAGE_RUNNERS.has(command)) {
    const pkg = args.find((a) => !a.startsWith("-"));
    if (pkg) return args.length > 1 ? `${command} ${pkg} …` : `${command} ${pkg}`;
  }
  return args.length > 0 ? `${command} …` : command;
}
