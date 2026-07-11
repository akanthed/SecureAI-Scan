#!/usr/bin/env node

import { runCli } from "./cli.js";

// Exit quietly when output is piped to a pager that closes early (head, less).
process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") process.exit(0);
  throw err;
});

await runCli(process.argv);
