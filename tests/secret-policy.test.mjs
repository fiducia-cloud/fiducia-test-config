import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtemp, mkdir, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";

import {
  hasSopsDotenvMetadata,
  isPlaintextDotenvPath,
  scanTrackedRepository,
  sensitiveTextRules,
} from "../src/secret-policy.mjs";

async function repository(files) {
  const root = await mkdtemp(join(tmpdir(), "fiducia-shared-secret-policy-test."));
  execFileSync("git", ["init", "-b", "main", root], { stdio: "ignore" });
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, { mode: 0o600 });
  }
  execFileSync("git", ["-C", root, "add", "--", "."], { stdio: "ignore" });
  return root;
}

function rules(findings) {
  return findings.map(({ rule }) => rule);
}

test("classifies plaintext dotenv names without rejecting examples or SOPS artifacts", () => {
  assert.equal(isPlaintextDotenvPath("deploy/customer/.env.production"), true);
  assert.equal(isPlaintextDotenvPath(".env.example"), false);
  assert.equal(isPlaintextDotenvPath("secrets/customer/dev.sops.env"), false);
  assert.equal(isPlaintextDotenvPath(".envrc"), false);
});

test("requires the complete SOPS dotenv metadata shape", () => {
  const metadata = [
    "sops_age__list_0__map_enc=fixture",
    "sops_age__list_0__map_recipient=age1fixture",
    "sops_mac=ENC[fixture]",
    "sops_version=3.13.3",
  ].join("\n");
  assert.equal(hasSopsDotenvMetadata(metadata), true);
  assert.equal(hasSopsDotenvMetadata(metadata.replace("sops_mac=", "missing_mac=")), false);
});

test("detects credential families but returns rule names rather than values", () => {
  const content = [
    ["AGE", "SECRET", "KEY"].join("-") + "-1FIXTUREONLY",
    "-----BEGIN " + "PRIVATE KEY-----",
    "gh" + "p_" + "A".repeat(36),
    "github_" + "pat_" + "B".repeat(50),
    "lin_" + "api_" + "C".repeat(30),
    "AK" + "IA" + "D".repeat(16),
  ].join("\n");
  assert.deepEqual(
    new Set(sensitiveTextRules(content)),
    new Set([
      "age-private-key",
      "pem-private-key",
      "github-classic-token",
      "github-fine-grained-token",
      "linear-api-token",
      "aws-access-key",
    ]),
  );
  assert.equal(JSON.stringify(sensitiveTextRules(content)).includes("FIXTUREONLY"), false);
});

test("accepts placeholders and structurally valid SOPS dotenv files", async () => {
  const root = await repository({
    ".env.example": "DATABASE_URL=\nTOKEN=replace-me\n",
    "secrets/README.md": "No plaintext values.\n",
    "secrets/customer/dev.sops.env": [
      "TOKEN=ENC[AES256_GCM,data:fixture,iv:fixture,tag:fixture,type:str]",
      "sops_age__list_0__map_enc=fixture",
      "sops_age__list_0__map_recipient=age1fixture",
      "sops_mac=ENC[fixture]",
      "sops_version=3.13.3",
    ].join("\n"),
  });
  assert.deepEqual(await scanTrackedRepository(root), []);
});

test("rejects plaintext, unencrypted secret paths, and malformed SOPS files", async () => {
  const root = await repository({
    "deploy/.env.local": "TOKEN=do-not-print-this-value\n",
    "secrets/customer/dev.env": "TOKEN=fixture\n",
    "secrets/admin/dev.sops.env": "TOKEN=fixture\n",
  });
  const findings = await scanTrackedRepository(root);
  assert.deepEqual(
    new Set(rules(findings)),
    new Set(["tracked-plaintext-env", "unencrypted-secret-path", "invalid-sops-dotenv"]),
  );
  assert.equal(JSON.stringify(findings).includes("do-not-print-this-value"), false);
});

test("the CLI fails without echoing a rejected value", async () => {
  const root = await repository({ ".env.local": "TOKEN=cli-do-not-print-this-value\n" });
  const script = join(import.meta.dirname, "..", "scripts", "check-secret-policy.mjs");
  const result = spawnSync(process.execPath, [script, "--root", root], { encoding: "utf8" });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /\.env\.local: tracked-plaintext-env/u);
  assert.equal(`${result.stdout}${result.stderr}`.includes("cli-do-not-print-this-value"), false);
});

test("refuses tracked symlinks rather than following their targets", async () => {
  const root = await repository({ "outside.txt": "safe fixture\n" });
  await symlink("outside.txt", join(root, "tracked-link.txt"));
  execFileSync("git", ["-C", root, "add", "--", "tracked-link.txt"], { stdio: "ignore" });
  assert.deepEqual(rules(await scanTrackedRepository(root)), ["tracked-symlink"]);
});

test("this repository satisfies the shared tracked-file policy", async () => {
  assert.deepEqual(await scanTrackedRepository(join(import.meta.dirname, "..")), []);
});
