/**
 * Which package does an `npx`/`uvx`/`pnpx`/`bunx` argument list launch?
 *
 * "The first argument that doesn't start with a dash" is wrong whenever an
 * option takes a value: in `npx --prefix ${PLUGIN_DATA} chrome-devtools-mcp@1.12.0`
 * the first bare word is the prefix directory, so a pinned package was reported
 * as unpinned (found scanning ChromeDevTools/chrome-devtools-mcp).
 */

/** Options that name the package itself; their value is the package. */
const PACKAGE_OPTIONS = new Set(["-p", "--package", "--from"]);

/** Options whose next argument is a value, not the package. */
const VALUE_OPTIONS = new Set([
  "--prefix",
  "--registry",
  "--cache",
  "--userconfig",
  "--workspace",
  "-w",
  "--python",
  "--with",
  "--node-options",
  "--shell",
]);

/** A bare argument that cannot be a registry package: a path, a URL, or an unexpanded variable. */
function looksLikePackageSpec(arg: string): boolean {
  if (/^(?:\$|%|~|\.{1,2}\/|\/|[a-z]:[\\/])/i.test(arg)) return false;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(arg)) return false;
  return /^(?:@[\w.-]+\/)?[\w.-]+(?:(?:@|[=<>~!]=?)[^\s]*)?$/.test(arg);
}

export function launchedPackage(args: string[]): string | undefined {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (PACKAGE_OPTIONS.has(arg)) {
      const value = args[i + 1];
      return value && looksLikePackageSpec(value) ? value : undefined;
    }
    const inline = /^(--package|--from)=(.+)$/.exec(arg);
    if (inline) return looksLikePackageSpec(inline[2]) ? inline[2] : undefined;
    if (VALUE_OPTIONS.has(arg)) {
      i++;
      continue;
    }
    if (arg.startsWith("-")) continue;
    return looksLikePackageSpec(arg) ? arg : undefined;
  }
  return undefined;
}
