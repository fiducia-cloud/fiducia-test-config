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
  validateSopsDotenv,
} from "../src/secret-policy.mjs";

async function repository(files) {
  const root = await mkdtemp(
    join(tmpdir(), "fiducia-shared-secret-policy-test."),
  );
  execFileSync("git", ["init", "-b", "main", root], { stdio: "ignore" });
  for (const [path, content] of Object.entries(files)) {
    const target = join(root, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, { mode: 0o600 });
  }
  execFileSync("git", ["-C", root, "add", "--", "."], {
    stdio: "ignore",
  });
  return root;
}

function sopsDotenv(
  value = "ENC[AES256_GCM,data:fixture,iv:fixture,tag:fixture,type:str]",
) {
  return [
    `TOKEN=${value}`,
    "sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nfixture\\n-----END AGE ENCRYPTED FILE-----\\n",
    "sops_age__list_0__map_recipient=age1fixturecustomerrecipient000000000000000000000000000000",
    "sops_lastmodified=2026-08-04T00:00:00Z",
    "sops_mac=ENC[AES256_GCM,data:fixture,iv:fixture,tag:fixture,type:str]",
    "sops_unencrypted_suffix=_unencrypted",
    "sops_version=3.13.3",
    "",
  ].join("\n");
}

function rules(findings) {
  return findings.map(({ rule }) => rule);
}

test("classifies plaintext dotenv names without rejecting examples or SOPS artifacts", () => {
  assert.equal(isPlaintextDotenvPath("deploy/customer/.env.production"), true);
  assert.equal(isPlaintextDotenvPath("config/service.env"), true);
  assert.equal(isPlaintextDotenvPath(".env.example"), false);
  assert.equal(isPlaintextDotenvPath("fixtures/service.env.template"), false);
  assert.equal(isPlaintextDotenvPath("env/enc/dev.env.enc"), false);
  assert.equal(isPlaintextDotenvPath("secrets/customer/dev.sops.env"), false);
  assert.equal(isPlaintextDotenvPath(".envrc"), false);
});

test("the compatibility metadata helper performs full SOPS dotenv validation", () => {
  assert.equal(hasSopsDotenvMetadata(sopsDotenv()), true);
  assert.equal(validateSopsDotenv(sopsDotenv("plaintext-value")), false);
  assert.equal(
    hasSopsDotenvMetadata(
      sopsDotenv().replace("sops_mac=", "missing_mac="),
    ),
    false,
  );
});

test("detects credential families but returns rule names rather than values", () => {
  const content = [
    ["AGE", "SECRET", "KEY"].join("-") + "-1FIXTUREONLY",
    "-----BEGIN " + "PRIVATE KEY-----",
    "gh" + "p_" + "A".repeat(36),
    "gh" + "s_" + "B".repeat(36),
    "github_" + "pat_" + "C".repeat(50),
    "lin_" + "api_" + "D".repeat(30),
    ["CHAT", "BRIDGE", "TOKEN"].join("_") + "=" + "E".repeat(40),
    "AK" + "IA" + "F".repeat(16),
  ].join("\n");
  assert.deepEqual(
    new Set(sensitiveTextRules(content)),
    new Set([
      "age-private-key",
      "pem-private-key",
      "github-classic-token",
      "github-other-token",
      "github-fine-grained-token",
      "linear-api-token",
      "google-chat-bridge-token",
      "aws-access-key",
    ]),
  );
  assert.equal(
    JSON.stringify(sensitiveTextRules(content)).includes("FIXTUREONLY"),
    false,
  );
});

test("accepts root SOPS config plus canonical and legacy encrypted dotenv paths", async () => {
  const root = await repository({
    ".sops.yaml": "creation_rules: []\n",
    ".env.example": "DATABASE_URL=\nTOKEN=replace-me\n",
    "env/README.md": "Only ciphertext is tracked.\n",
    "env/enc/dev.env.enc": sopsDotenv(),
    "secrets/README.md": "No plaintext values.\n",
    "secrets/customer/dev.sops.env": sopsDotenv(),
  });
  assert.deepEqual(await scanTrackedRepository(root), []);
});

test("canonical env ciphertext supports dev and prod but rejects local aliases", async () => {
  const root = await repository({
    "env/enc/dev.env.enc": sopsDotenv(),
    "env/enc/prod.env.enc": sopsDotenv(),
    "env/enc/local.env.enc": sopsDotenv(),
  });

  assert.deepEqual(rules(await scanTrackedRepository(root)), [
    "noncanonical-encrypted-env",
  ]);
});

test("rejects plaintext values hidden beside valid-looking canonical SOPS metadata", async () => {
  const root = await repository({
    "env/enc/dev.env.enc": sopsDotenv("plaintext-value"),
  });
  assert.deepEqual(rules(await scanTrackedRepository(root)), [
    "invalid-sops-dotenv",
  ]);
});

test("rejects unapproved SOPS paths and unsupported legacy formats", async () => {
  const root = await repository({
    "deploy/customer/dev.sops.env": sopsDotenv(),
    "env/enc/local.env.enc": sopsDotenv(),
    "secrets/customer/dev.sops.json": JSON.stringify({
      token: "plaintext",
      sops: { mac: "ENC[fixture]", version: "3.13.3" },
    }),
  });
  assert.deepEqual(
    new Set(rules(await scanTrackedRepository(root))),
    new Set([
      "sops-outside-approved-path",
      "noncanonical-encrypted-env",
      "unsupported-sops-format",
    ]),
  );
});

test("root SOPS configuration remains subject to credential-signature scanning", async () => {
  const root = await repository({
    ".sops.yaml": "comment: -----BEGIN " + "PRIVATE KEY-----\n",
  });

  assert.deepEqual(rules(await scanTrackedRepository(root)), ["pem-private-key"]);
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
    new Set([
      "tracked-plaintext-env",
      "unencrypted-secret-path",
      "invalid-sops-dotenv",
    ]),
  );
  assert.equal(
    JSON.stringify(findings).includes("do-not-print-this-value"),
    false,
  );
});

test("rejects arbitrary plaintext files placed under env/enc", async () => {
  const root = await repository({
    "env/enc/notes.txt": "TOKEN=fixture\n",
  });

  assert.deepEqual(rules(await scanTrackedRepository(root)), [
    "unencrypted-secret-path",
  ]);
});

test("scans credentials in NUL-containing tracked files", async () => {
  const root = await repository({
    "binary-fixture.bin": Buffer.concat([
      Buffer.from([0, 1, 2]),
      Buffer.from("gh" + "p_" + "A".repeat(36)),
      Buffer.from([0, 3]),
    ]),
  });
  assert.deepEqual(rules(await scanTrackedRepository(root)), [
    "github-classic-token",
  ]);
});

test("fails closed on oversized tracked regular files", async () => {
  const root = await repository({
    "large-fixture.txt": "x".repeat(1024 * 1024 + 1),
  });
  const findings = await scanTrackedRepository(root);
  assert.deepEqual(rules(findings), ["oversized-tracked-file"]);
  assert.equal(JSON.stringify(findings).includes("x".repeat(100)), false);
});

test("the CLI fails without echoing a rejected value", async () => {
  const root = await repository({
    ".env.local": "TOKEN=cli-do-not-print-this-value\n",
  });
  const script = join(
    import.meta.dirname,
    "..",
    "scripts",
    "check-secret-policy.mjs",
  );
  const result = spawnSync(process.execPath, [script, "--root", root], {
    encoding: "utf8",
  });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /\.env\.local: tracked-plaintext-env/u);
  assert.equal(
    `${result.stdout}${result.stderr}`.includes(
      "cli-do-not-print-this-value",
    ),
    false,
  );
});

test("refuses tracked symlinks rather than following their targets", async () => {
  const root = await repository({ "outside.txt": "safe fixture\n" });
  await symlink("outside.txt", join(root, "tracked-link.txt"));
  execFileSync("git", ["-C", root, "add", "--", "tracked-link.txt"], {
    stdio: "ignore",
  });
  assert.deepEqual(rules(await scanTrackedRepository(root)), [
    "tracked-symlink",
  ]);
});

test("this repository satisfies the shared tracked-file policy", async () => {
  assert.deepEqual(
    await scanTrackedRepository(join(import.meta.dirname, "..")),
    [],
  );
});
