#!/usr/bin/env node

import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { scanTrackedRepository } from "../src/secret-policy.mjs";

function parseRoot(argv) {
  const index = argv.indexOf("--root");
  if (index === -1) return dirname(dirname(fileURLToPath(import.meta.url)));
  if (!argv[index + 1]) throw new Error("--root requires a path");
  return resolve(argv[index + 1]);
}

const findings = await scanTrackedRepository(parseRoot(process.argv.slice(2)));
if (findings.length === 0) {
  process.stdout.write("secret policy OK: tracked files contain no prohibited plaintext material\n");
} else {
  for (const item of findings) {
    process.stderr.write(`${item.path}: ${item.rule}: ${item.detail}\n`);
  }
  process.stderr.write(`secret policy FAIL: ${findings.length} finding(s); values were not printed\n`);
  process.exitCode = 1;
}
