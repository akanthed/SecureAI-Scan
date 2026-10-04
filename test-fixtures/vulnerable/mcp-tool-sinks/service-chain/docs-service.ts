import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

export class DocsService {
  async describe(pkg: string, symbol?: string): Promise<string> {
    // A routing branch on the value, not validation of it.
    const source = pkg.includes("internal") ? "internal" : "public";
    return this.run(symbol ? `go doc ${pkg}.${symbol}` : `go doc ${pkg}`, source);
  }

  private async run(command: string, source: string): Promise<string> {
    const { stdout } = await execAsync(command);
    return `${source}: ${stdout}`;
  }
}
