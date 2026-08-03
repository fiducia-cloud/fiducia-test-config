import assert from "node:assert/strict";
import test from "node:test";

import { startStubSharedAuth } from "../src/shared-auth-stub.mjs";
import { verifyEs256Jwt } from "../src/stubs.mjs";

const PROJECT = "fiducia-customer";
const IDENTITY = {
  providerToken: "provider-customer-token",
  sharedUserId: "shared-user-1",
  providerSubject: "11111111-1111-4111-8111-111111111111",
  project: PROJECT,
  roles: ["customer"],
  email: "customer@example.invalid",
  emailVerified: true,
  sessionId: "22222222-2222-4222-8222-222222222222",
};

async function exchange(stub, token = IDENTITY.providerToken) {
  return fetch(`${stub.url}/auth/exchange`, {
    method: "POST",
    headers: { authorization: `Bearer ${token}` },
  });
}

async function introspect(stub, token, secret = stub.introspectSecret) {
  return fetch(`${stub.url}/auth/introspect`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${secret}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ token }),
  });
}

test("exchange issues one coherent ES256 access token with no refresh credential", async (t) => {
  const stub = await startStubSharedAuth({ project: PROJECT, identities: [IDENTITY] });
  t.after(() => stub.stop());

  const jwksResponse = await fetch(`${stub.url}/.well-known/jwks.json`);
  assert.equal(jwksResponse.status, 200);
  assert.equal(jwksResponse.headers.get("cache-control"), "no-store");
  const jwks = await jwksResponse.json();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kty, "EC");
  assert.equal(jwks.keys[0].crv, "P-256");
  assert.equal(jwks.keys[0].alg, "ES256");
  assert.equal(jwks.keys[0].use, "sig");

  const response = await exchange(stub);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const issued = await response.json();
  assert.equal(issued.token_type, "Bearer");
  assert.equal(issued.provider, "supabase");
  assert.equal(issued.provider_tenant, PROJECT);
  assert.equal(issued.provider_subject, IDENTITY.providerSubject);
  assert.equal(issued.shared_user_id, IDENTITY.sharedUserId);
  assert.deepEqual(issued.roles, ["customer"]);
  assert.equal("refresh_token" in issued, false, "browser fixture must never return a refresh token");

  const claims = verifyEs256Jwt(stub.jwk, issued.access_token);
  assert.ok(claims, "issued access token verifies against the fixture JWKS");
  assert.equal(claims.iss, stub.issuer);
  assert.equal(claims.aud, stub.audience);
  assert.equal(claims.sub, IDENTITY.sharedUserId);
  assert.equal(claims.provider, "supabase");
  assert.equal(claims.provider_tenant, PROJECT);
  assert.equal(claims.project, PROJECT);
  assert.equal(claims.supabase_user_id, IDENTITY.providerSubject);
  assert.equal(claims.sid, IDENTITY.sessionId);
  assert.deepEqual(claims.roles, ["customer"]);
  assert.ok(claims.exp > Math.floor(Date.now() / 1000));

  const introspection = await introspect(stub, issued.access_token);
  assert.equal(introspection.status, 200);
  const active = await introspection.json();
  assert.equal(active.active, true);
  assert.equal(active.sub, IDENTITY.sharedUserId);
  assert.equal(active.provider_tenant, PROJECT);
  assert.equal(active.project, PROJECT);
  assert.equal(active.supabase_user_id, IDENTITY.providerSubject);
  assert.equal(active.sid, IDENTITY.sessionId);
  assert.deepEqual(active.roles, ["customer"]);

  assert.deepEqual(stub.requestCounts, { jwks: 1, exchange: 1, introspect: 1 });
});

test("exchange rejects an unknown provider credential without minting anything", async (t) => {
  const stub = await startStubSharedAuth({ project: PROJECT, identities: [IDENTITY] });
  t.after(() => stub.stop());

  const response = await exchange(stub, "unknown-provider-token");
  assert.equal(response.status, 401);
  assert.deepEqual(await response.json(), { error: "invalid_provider_token" });
  assert.deepEqual(stub.requestCounts, { jwks: 0, exchange: 1, introspect: 0 });
});

test("introspection requires its internal secret and rejects malformed or oversized bodies", async (t) => {
  const stub = await startStubSharedAuth({ project: PROJECT, identities: [IDENTITY] });
  t.after(() => stub.stop());

  const issued = await (await exchange(stub)).json();

  const wrongSecret = await introspect(stub, issued.access_token, "wrong-secret");
  assert.equal(wrongSecret.status, 401);
  assert.deepEqual(await wrongSecret.json(), {
    active: false,
    error: "invalid_introspection_secret",
  });

  const malformed = await fetch(`${stub.url}/auth/introspect`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${stub.introspectSecret}`,
      "content-type": "application/json",
    },
    body: "not-json",
  });
  assert.equal(malformed.status, 400);
  assert.equal((await malformed.json()).active, false);

  const oversized = await fetch(`${stub.url}/auth/introspect`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${stub.introspectSecret}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ token: "x".repeat(70 * 1024) }),
  });
  assert.equal(oversized.status, 413);
  assert.equal((await oversized.json()).active, false);

  assert.deepEqual(stub.requestCounts, { jwks: 0, exchange: 1, introspect: 3 });
});

test("expired, wrong-issuer, wrong-audience, and tampered tokens introspect inactive", async (t) => {
  const stub = await startStubSharedAuth({ project: PROJECT });
  t.after(() => stub.stop());

  const now = Math.floor(Date.now() / 1000);
  const expired = stub.signSharedToken(IDENTITY, { expiresAt: now - 1 });
  const wrongIssuer = stub.signSharedToken(IDENTITY, {
    issuer: "https://foreign-auth.fiducia.invalid",
  });
  const wrongAudience = stub.signSharedToken(IDENTITY, { audience: "fiducia-admin" });
  const genuine = stub.signSharedToken(IDENTITY);
  const [header, payload, signature] = genuine.split(".");
  const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
  claims.roles = ["admin"];
  const tampered = `${header}.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${signature}`;

  for (const token of [expired, wrongIssuer, wrongAudience, tampered, "not-a-jwt"]) {
    const response = await introspect(stub, token);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { active: false });
  }

  assert.equal(stub.requestCounts.introspect, 5);
});

test("foreign provider-project claims remain visible for consumer rejection tests", async (t) => {
  const stub = await startStubSharedAuth({ project: PROJECT });
  t.after(() => stub.stop());

  const foreign = stub.signSharedToken({
    ...IDENTITY,
    project: "fiducia-admin",
    roles: ["admin"],
    sessionId: "33333333-3333-4333-8333-333333333333",
  });
  const response = await introspect(stub, foreign);
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.active, true);
  assert.equal(body.provider_tenant, "fiducia-admin");
  assert.equal(body.project, "fiducia-admin");
  assert.deepEqual(body.roles, ["admin"]);
});

test("fixture configuration and identities fail closed before listening", async () => {
  await assert.rejects(() => startStubSharedAuth({ project: "" }), /invalid Shared Auth fixture configuration/);
  await assert.rejects(
    () =>
      startStubSharedAuth({
        project: PROJECT,
        identities: [{ ...IDENTITY, providerSubject: "bad/subject" }],
      }),
    /invalid Shared Auth fixture identity/,
  );
  await assert.rejects(
    () =>
      startStubSharedAuth({
        project: PROJECT,
        identities: [IDENTITY, { ...IDENTITY, sharedUserId: "shared-user-2" }],
      }),
    /duplicate provider token/,
  );
});
