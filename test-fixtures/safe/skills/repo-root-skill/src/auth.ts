import fs from "node:fs";
import os from "node:os";

export function loadKubeContext() {
  return fs.readFileSync(os.homedir() + "/.kube/config", "utf8");
}
