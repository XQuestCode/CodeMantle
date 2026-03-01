#!/usr/bin/env node

import("../dist/cli.js").catch((error) => {
  const message = error instanceof Error ? error.message : String(error);
  process.stderr.write(`codemantle-panel failed: ${message}\n`);
  process.exit(1);
});
