// Self-tests for the stub Supabase + Fiducia-KV fixtures. These prove the wire
// shapes the real Rust consumers depend on (fiducia-auth's supabase.rs, sync.rs,
// store.rs; fiducia-admin's login_submit; supabase-js password login), so app
// repos can lean on the stubs without re-verifying them.

import assert from "node:assert/strict";
import test from "node:test";

import {
  fiduciaAuthStubEnv,
  generateP256PrivateKeyPem,
  startStubFiduciaKv,
  startStubSupabase,
  verifyEs256Jwt,
} from "../src/stubs.mjs";

const OPERATOR = {
  id: "op-1",
  email: "ops@fiducia.cloud",
  password: "operator-pw",
  app_metadata: { orgs: ["org_infra"], roles: ["admin"] },
};
const CUSTOMER = {
  id: "cust-1",
  email: "dev@acme.com",
  password: "customer-pw",
  app_metadata: { orgs: ["org_acme"] },
};

test("jwks endpoint serves a single asymmetric ES256 P-256 key", async () => {
  const stub = await startStubSupabase({ users: [OPERATOR] });
  try {
    const jwks = await (await fetch(stub.jwksUrl)).json();
    assert.equal(jwks.keys.length, 1);
    const [key] = jwks.keys;
    assert.equal(key.kty, "EC"); // asymmetric — fiducia-auth rejects oct keys
    assert.equal(key.crv, "P-256");
    assert.equal(key.alg, "ES256");
    assert.equal(key.use, "sig");
    assert.ok(key.kid, "kid required for fiducia-auth's JWKS lookup");
  } finally {
    await stub.stop();
  }
});

test("password grant returns a session whose JWT carries the fiducia-auth claim contract", async () => {
  const stub = await startStubSupabase({ users: [OPERATOR, CUSTOMER] });
  try {
    const response = await fetch(`${stub.url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "content-type": "application/json", apikey: "anon-key" },
      body: JSON.stringify({ email: "Ops@Fiducia.Cloud", password: "operator-pw" }),
    });
    assert.equal(response.status, 200);
    const session = await response.json();
    assert.equal(session.token_type, "bearer");
    assert.ok(session.refresh_token);
    assert.ok(session.expires_in > 0);
    assert.equal(session.user.email, "ops@fiducia.cloud");

    const claims = verifyEs256Jwt(stub.jwk, session.access_token);
    assert.ok(claims, "signature must verify against the served JWKS");
    assert.equal(claims.iss, stub.issuer);
    assert.equal(claims.aud, "authenticated");
    assert.equal(claims.role, "authenticated");
    assert.equal(claims.sub, "op-1");
    assert.deepEqual(claims.app_metadata.roles, ["admin"]);
    assert.deepEqual(claims.app_metadata.orgs, ["org_infra"]);
    assert.ok(claims.exp > Math.floor(Date.now() / 1000));
  } finally {
    await stub.stop();
  }
});

test("password grant rejects bad credentials and missing apikey", async () => {
  const stub = await startStubSupabase({ users: [OPERATOR] });
  try {
    const wrongPassword = await fetch(`${stub.url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "content-type": "application/json", apikey: "anon-key" },
      body: JSON.stringify({ email: OPERATOR.email, password: "nope" }),
    });
    assert.equal(wrongPassword.status, 400);

    const noApikey = await fetch(`${stub.url}/auth/v1/token?grant_type=password`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: OPERATOR.email, password: OPERATOR.password }),
    });
    assert.equal(noApikey.status, 401, "forgotten apikey wiring should fail loudly");
  } finally {
    await stub.stop();
  }
});

test("refresh grant rotates sessions and /auth/v1/user resolves bearers", async () => {
  const stub = await startStubSupabase({ users: [CUSTOMER] });
  try {
    const first = await (
      await fetch(`${stub.url}/auth/v1/token?grant_type=password`, {
        method: "POST",
        headers: { "content-type": "application/json", apikey: "anon-key" },
        body: JSON.stringify({ email: CUSTOMER.email, password: CUSTOMER.password }),
      })
    ).json();

    const refreshed = await fetch(`${stub.url}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST",
      headers: { "content-type": "application/json", apikey: "anon-key" },
      body: JSON.stringify({ refresh_token: first.refresh_token }),
    });
    assert.equal(refreshed.status, 200);

    const me = await fetch(`${stub.url}/auth/v1/user`, {
      headers: { apikey: "anon-key", authorization: `Bearer ${first.access_token}` },
    });
    assert.equal(me.status, 200);
    assert.equal((await me.json()).id, "cust-1");

    const garbage = await fetch(`${stub.url}/auth/v1/user`, {
      headers: { apikey: "anon-key", authorization: "Bearer garbage" },
    });
    assert.equal(garbage.status, 401);
  } finally {
    await stub.stop();
  }
});

test("signAccessToken overrides support negative-path tokens (expired, wrong role)", async () => {
  const stub = await startStubSupabase({ users: [CUSTOMER] });
  try {
    const expired = stub.signAccessToken(CUSTOMER, {
      claims: { exp: Math.floor(Date.now() / 1000) - 60 },
    });
    const claims = verifyEs256Jwt(stub.jwk, expired);
    assert.ok(claims.exp < Math.floor(Date.now() / 1000));

    const serviceRole = stub.signAccessToken(CUSTOMER, { claims: { role: "service_role" } });
    assert.equal(verifyEs256Jwt(stub.jwk, serviceRole).role, "service_role");
  } finally {
    await stub.stop();
  }
});

test("identity stub fails closed: missing, expired, and forged tokens are 401; only the real one passes", async (t) => {
  // If the harness's own identity service accepted a bad token, every
  // downstream auth test built on it would be vacuous.
  const stub = await startStubSupabase({ users: [CUSTOMER] });
  const imposter = await startStubSupabase({ users: [CUSTOMER] }); // same user, DIFFERENT signing key
  t.after(async () => {
    await stub.stop();
    await imposter.stop();
  });

  const me = (token) =>
    fetch(`${stub.url}/auth/v1/user`, {
      headers: {
        apikey: "anon-key",
        ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
      },
    });

  // No token at all.
  assert.equal((await me(undefined)).status, 401);

  // Expired but genuinely signed token.
  const expired = stub.signAccessToken(CUSTOMER, {
    claims: { exp: Math.floor(Date.now() / 1000) - 60 },
  });
  assert.equal((await me(expired)).status, 401);

  // Forged token: valid ES256 signature, correct claims, WRONG key.
  const forged = imposter.signAccessToken(CUSTOMER);
  assert.equal((await me(forged)).status, 401, "a token signed by a foreign key must be rejected");

  // Tampered payload over a genuine signature.
  const genuine = stub.signAccessToken(CUSTOMER);
  const [head, body, sig] = genuine.split(".");
  const swollen = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  swollen.app_metadata = { orgs: ["org_infra"], roles: ["admin"] };
  const tampered = `${head}.${Buffer.from(JSON.stringify(swollen)).toString("base64url")}.${sig}`;
  assert.equal((await me(tampered)).status, 401);

  // The configured token still passes — fail-closed, not fail-always.
  const accepted = await me(genuine);
  assert.equal(accepted.status, 200);
  assert.equal((await accepted.json()).id, CUSTOMER.id);
});

test("rest serves the organizations table for fiducia-auth's org sync", async () => {
  const stub = await startStubSupabase({
    orgs: [{ id: "org_acme", plan: "pro" }],
  });
  try {
    const rows = await (
      await fetch(`${stub.url}/rest/v1/organizations?select=*`, {
        headers: { apikey: "service-role", authorization: "Bearer service-role" },
      })
    ).json();
    assert.deepEqual(rows, [{ id: "org_acme", plan: "pro" }]);

    const other = await (
      await fetch(`${stub.url}/rest/v1/widgets?select=*`, {
        headers: { apikey: "service-role" },
      })
    ).json();
    assert.deepEqual(other, []);
  } finally {
    await stub.stop();
  }
});

test("kv stub speaks fiducia-auth's store contract: get/put/CAS envelopes", async () => {
  const kv = await startStubFiduciaKv();
  try {
    const missing = await (await fetch(`${kv.url}/v1/kv?key=__auth/keys/k1`)).json();
    assert.deepEqual(missing, { found: false });

    const putNew = async (prevRevision, value) =>
      (
        await fetch(`${kv.url}/v1/kv?key=__auth/keys/k1`, {
          method: "PUT",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ value: JSON.stringify(value), prev_revision: prevRevision }),
        })
      ).json();

    // prev_revision 0 = "must not exist" — first write applies.
    const created = await putNew(0, { key_id: "k1", revoked: false });
    assert.equal(created.committed, true);
    assert.equal(created.result.output.ok, true);
    const revision = created.result.output.revision;
    assert.ok(revision >= 1);

    // Stale CAS reports mismatch with the current revision, still committed:true.
    const stale = await putNew(0, { key_id: "k1", revoked: true });
    assert.equal(stale.committed, true);
    assert.equal(stale.result.output.ok, false);
    assert.equal(stale.result.output.reason, "cas_mismatch");
    assert.equal(stale.result.output.current_revision, revision);

    // Correct CAS applies; unconditional (null) always applies.
    const updated = await putNew(revision, { key_id: "k1", revoked: true });
    assert.equal(updated.result.output.ok, true);
    const unconditional = await putNew(null, { key_id: "k1", revoked: false });
    assert.equal(unconditional.result.output.ok, true);

    const fetched = await (await fetch(`${kv.url}/v1/kv?key=__auth/keys/k1`)).json();
    assert.equal(fetched.found, true);
    assert.deepEqual(JSON.parse(fetched.entry.value), { key_id: "k1", revoked: false });
    assert.equal(fetched.entry.mod_revision, unconditional.result.output.revision);
  } finally {
    await kv.stop();
  }
});

test("fiduciaAuthStubEnv wires both stubs plus a parseable signing key", async () => {
  const stub = await startStubSupabase({ users: [OPERATOR] });
  const kv = await startStubFiduciaKv();
  try {
    const env = fiduciaAuthStubEnv(stub, kv);
    assert.equal(env.SUPABASE_URL, stub.url);
    assert.equal(env.SUPABASE_AUTH_JWKS_URL, stub.jwksUrl);
    assert.equal(env.FIDUCIA_KV_URL, kv.url);
    assert.match(env.FIDUCIA_JWT_SIGNING_KEY, /^-----BEGIN PRIVATE KEY-----/);
    assert.match(generateP256PrivateKeyPem(), /-----END PRIVATE KEY-----\s*$/);
  } finally {
    await stub.stop();
    await kv.stop();
  }
});
