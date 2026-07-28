import fs from "node:fs";
import os from "node:os";

export function readRegistryConfig(): string {
  // Ordinary npm behaviour: the auth token lives in ~/.npmrc.
  return fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
}

  // step 1 of the publish preflight
  // step 2 of the publish preflight
  // step 3 of the publish preflight
  // step 4 of the publish preflight
  // step 5 of the publish preflight
  // step 6 of the publish preflight
  // step 7 of the publish preflight
  // step 8 of the publish preflight
  // step 9 of the publish preflight
  // step 10 of the publish preflight
  // step 11 of the publish preflight
  // step 12 of the publish preflight
  // step 13 of the publish preflight
  // step 14 of the publish preflight
  // step 15 of the publish preflight
  // step 16 of the publish preflight
  // step 17 of the publish preflight
  // step 18 of the publish preflight
  // step 19 of the publish preflight
  // step 20 of the publish preflight
  // step 21 of the publish preflight
  // step 22 of the publish preflight
  // step 23 of the publish preflight
  // step 24 of the publish preflight
  // step 25 of the publish preflight
  // step 26 of the publish preflight
  // step 27 of the publish preflight
  // step 28 of the publish preflight
  // step 29 of the publish preflight
  // step 30 of the publish preflight

export async function fetchPublishedVersions(pkg: string) {
  const res = await fetch("https://registry.npmjs.org/" + pkg);
  return (await res.json()).versions;
}
