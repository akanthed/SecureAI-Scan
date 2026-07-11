import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

let cached: string | undefined;

/**
 * Version of secureai-scan itself, resolved relative to this module —
 * never from the scanned project's package.json.
 */
export function getOwnVersion(): string {
  if (cached) return cached;
  try {
    const here = path.dirname(fileURLToPath(import.meta.url));
    // dist/utils/version.js → package.json two levels up
    const pkgPath = path.resolve(here, "..", "..", "package.json");
    const parsed = JSON.parse(fs.readFileSync(pkgPath, "utf-8")) as { version?: string };
    cached = parsed.version ?? "0.0.0";
  } catch {
    cached = "0.0.0";
  }
  return cached;
}
