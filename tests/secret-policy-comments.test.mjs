import assert from "node:assert/strict";
import test from "node:test";

import { validateSopsDotenv } from "../src/secret-policy.mjs";

const encrypted =
  "ENC[AES256_GCM,data:fixture,iv:fixture,tag:fixture,type:comment]";

function commentOnlySopsDotenv(comment = `#${encrypted}`) {
  return [
    comment,
    "sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\\nfixture\\n-----END AGE ENCRYPTED FILE-----\\n",
    "sops_age__list_0__map_recipient=age1fixturecustomerrecipient000000000000000000000000000000",
    "sops_lastmodified=2026-08-04T00:00:00Z",
    "sops_mac=ENC[AES256_GCM,data:fixture,iv:fixture,tag:fixture,type:str]",
    "sops_unencrypted_suffix=_unencrypted",
    "sops_version=3.13.3",
    "",
  ].join("\n");
}

test("accepts a SOPS dotenv whose payload consists of encrypted comments", () => {
  assert.equal(validateSopsDotenv(commentOnlySopsDotenv()), true);
});

test("rejects plaintext comments inside an approved ciphertext artifact", () => {
  assert.equal(
    validateSopsDotenv(commentOnlySopsDotenv("# plaintext fixture")),
    false,
  );
});

test("rejects metadata-only documents with no encrypted payload", () => {
  assert.equal(validateSopsDotenv(commentOnlySopsDotenv("")), false);
});
