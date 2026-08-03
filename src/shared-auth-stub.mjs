// Deterministic Shared Auth HTTP/JWT fixture for real-browser E2E.
//
// This is intentionally narrower than the production service. It models only
// the contracts consumed by Fiducia applications:
//   GET  /.well-known/jwks.json
//   POST /auth/exchange
//   POST /auth/introspect
//
// The fixture signs ES256 JWTs, pins every identity to one provider project,
// requires the internal introspection secret, bounds request bodies, and never
// returns a refresh token. Tests can inspect request counts without retaining
// raw credentials in logs.

import { createServer } from "node:http";
import {
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

const MAX_BODY_BYTES = 64 * 1024;
const MAX_TOKEN_BYTES = 16 * 1024;
const MAX_IDENTIFIER_BYTES = 200;

const b64url = (value) => Buffer.from(value).toString("base64url");

function validIdentifier(value) {
  return (
    typeof value === "string" &&
    value.trim().length > 0 &&
    Buffer.byteLength(value) <= MAX_IDENTIFIER_BYTES &&
    !/[\u0000-\u001f\u007f/\\]/u.test(value)
  );
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
    "cache-control": "no-store",
  });
  res.end(payload);
}

async function readJson(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      const error = new Error("request body exceeds fixture limit");
      error.code = "BODY_TOO_LARGE";
      throw error;
    }
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");
  return raw ? JSON.parse(raw) : {};
}

function signEs256Jwt(privateKey, kid, claims, algorithm = "ES256") {
  if (algorithm !== "ES256") {
    throw new Error("Shared Auth fixture signs ES256 only");
  }
  const header = { alg: algorithm, typ: "JWT", kid };
  const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  const signature = cryptoSign("sha256", Buffer.from(input), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${input}.${b64url(signature)}`;
}

function verifyEs256Jwt(publicKey, token) {
  if (typeof token !== "string" || token.length > MAX_TOKEN_BYTES) {
    return null;
  }
  const parts = token.split(".");
  if (parts.length !== 3) {
    return null;
  }
  let header;
  let claims;
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (header.alg !== "ES256" || typeof header.kid !== "string") {
    return null;
  }
  const valid = cryptoVerify(
    "sha256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    { key: publicKey, dsaEncoding: "ieee-p1363" },
    Buffer.from(parts[2], "base64url"),
  );
  return valid ? { header, claims } : null;
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      resolve(`http://127.0.0.1:${server.address().port}`);
    });
  });
}

function stopServer(server) {
  return () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(() => resolve());
    });
}

function normalizeIdentity(identity, defaultProject) {
  const project = identity.project ?? defaultProject;
  const sharedUserId = identity.sharedUserId;
  const providerSubject = identity.providerSubject;
  const providerToken = identity.providerToken;
  const roles = [...(identity.roles ?? [])];

  if (
    !validIdentifier(project) ||
    !validIdentifier(sharedUserId) ||
    !validIdentifier(providerSubject) ||
    typeof providerToken !== "string" ||
    providerToken.length === 0 ||
    providerToken.length > MAX_TOKEN_BYTES ||
    roles.some((role) => !validIdentifier(role))
  ) {
    throw new Error("invalid Shared Auth fixture identity");
  }

  return {
    providerToken,
    sharedUserId,
    providerSubject,
    project,
    roles,
    email: identity.email ?? null,
    emailVerified: identity.emailVerified ?? true,
    sessionId: identity.sessionId ?? null,
  };
}

/**
 * Start a strict Shared Auth fixture on an ephemeral loopback port.
 *
 * @param {object} options
 * @param {string} options.project expected Supabase provider project
 * @param {string} [options.issuer] JWT issuer
 * @param {string} [options.audience] JWT audience
 * @param {string} [options.introspectSecret] internal introspection bearer
 * @param {number} [options.accessTokenTtlSeconds]
 * @param {Array<{
 *   providerToken: string,
 *   sharedUserId: string,
 *   providerSubject: string,
 *   project?: string,
 *   roles?: string[],
 *   email?: string,
 *   emailVerified?: boolean,
 *   sessionId?: string,
 * }>} [options.identities]
 * @returns {Promise<{
 *   url: string,
 *   issuer: string,
 *   audience: string,
 *   project: string,
 *   jwk: object,
 *   introspectSecret: string,
 *   requestCounts: Readonly<{jwks: number, exchange: number, introspect: number}>,
 *   signSharedToken: (identity: object, overrides?: object) => string,
 *   stop: () => Promise<void>,
 * }>}
 */
export async function startStubSharedAuth({
  project,
  issuer = "https://auth.fiducia.invalid",
  audience = "fiducia",
  introspectSecret = "fixture-introspect-secret",
  accessTokenTtlSeconds = 3600,
  identities = [],
} = {}) {
  if (
    !validIdentifier(project) ||
    !validIdentifier(audience) ||
    !validIdentifier(introspectSecret) ||
    typeof issuer !== "string" ||
    !issuer.startsWith("https://") ||
    !Number.isSafeInteger(accessTokenTtlSeconds) ||
    accessTokenTtlSeconds <= 0
  ) {
    throw new Error("invalid Shared Auth fixture configuration");
  }

  const normalized = identities.map((identity) => normalizeIdentity(identity, project));
  const byProviderToken = new Map();
  for (const identity of normalized) {
    if (byProviderToken.has(identity.providerToken)) {
      throw new Error("duplicate provider token in Shared Auth fixture");
    }
    byProviderToken.set(identity.providerToken, identity);
  }

  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = `shared-${randomBytes(8).toString("hex")}`;
  const jwk = {
    ...publicKey.export({ format: "jwk" }),
    kid,
    use: "sig",
    alg: "ES256",
  };
  const counts = { jwks: 0, exchange: 0, introspect: 0 };

  const signSharedToken = (identityInput, overrides = {}) => {
    const identity = normalizeIdentity(
      {
        providerToken: identityInput.providerToken ?? "fixture-provider-token",
        sharedUserId: identityInput.sharedUserId,
        providerSubject: identityInput.providerSubject,
        project: identityInput.project ?? project,
        roles: identityInput.roles ?? [],
        email: identityInput.email,
        emailVerified: identityInput.emailVerified,
        sessionId: identityInput.sessionId,
      },
      project,
    );
    const now = Math.floor(Date.now() / 1000);
    return signEs256Jwt(privateKey, overrides.kid ?? kid, {
      iss: overrides.issuer ?? issuer,
      aud: overrides.audience ?? audience,
      sub: identity.sharedUserId,
      provider: "supabase",
      provider_tenant: identity.project,
      provider_subject: identity.providerSubject,
      project: identity.project,
      supabase_user_id: identity.providerSubject,
      sid: overrides.sessionId ?? identity.sessionId ?? randomUUID(),
      email: identity.email,
      email_verified: identity.emailVerified,
      roles: overrides.roles ?? identity.roles,
      iat: now,
      exp: overrides.expiresAt ?? now + accessTokenTtlSeconds,
      ...overrides.claims,
    });
  };

  const server = createServer(async (req, res) => {
    const path = new URL(req.url, "http://stub").pathname;

    if (req.method === "GET" && path === "/healthz") {
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === "GET" && path === "/.well-known/jwks.json") {
      counts.jwks += 1;
      return sendJson(res, 200, { keys: [jwk] });
    }

    if (req.method === "POST" && path === "/auth/exchange") {
      counts.exchange += 1;
      const providerToken = String(req.headers.authorization ?? "").replace(/^Bearer /, "");
      const identity = byProviderToken.get(providerToken);
      if (!identity) {
        return sendJson(res, 401, { error: "invalid_provider_token" });
      }
      const sessionId = identity.sessionId ?? randomUUID();
      const accessToken = signSharedToken(identity, { sessionId });
      return sendJson(res, 200, {
        access_token: accessToken,
        token_type: "Bearer",
        expires_in: accessTokenTtlSeconds,
        shared_user_id: identity.sharedUserId,
        provider: "supabase",
        provider_tenant: identity.project,
        provider_subject: identity.providerSubject,
        roles: identity.roles,
      });
    }

    if (req.method === "POST" && path === "/auth/introspect") {
      counts.introspect += 1;
      if (req.headers.authorization !== `Bearer ${introspectSecret}`) {
        return sendJson(res, 401, { active: false, error: "invalid_introspection_secret" });
      }

      let body;
      try {
        body = await readJson(req);
      } catch (error) {
        return sendJson(res, error.code === "BODY_TOO_LARGE" ? 413 : 400, {
          active: false,
          error: "invalid_introspection_request",
        });
      }

      const verified = verifyEs256Jwt(publicKey, body.token);
      const now = Math.floor(Date.now() / 1000);
      const claims = verified?.claims;
      if (
        !claims ||
        claims.iss !== issuer ||
        claims.aud !== audience ||
        !Number.isFinite(claims.exp) ||
        claims.exp <= now
      ) {
        return sendJson(res, 200, { active: false });
      }

      return sendJson(res, 200, {
        active: true,
        sub: claims.sub,
        provider: claims.provider,
        provider_tenant: claims.provider_tenant,
        provider_subject: claims.provider_subject,
        project: claims.project,
        supabase_user_id: claims.supabase_user_id,
        sid: claims.sid,
        email: claims.email,
        email_verified: claims.email_verified,
        roles: claims.roles ?? [],
        exp: claims.exp,
      });
    }

    return sendJson(res, 404, { error: `no fixture route for ${req.method} ${path}` });
  });

  const url = await listen(server);
  return {
    url,
    issuer,
    audience,
    project,
    jwk,
    introspectSecret,
    requestCounts: counts,
    signSharedToken,
    stop: stopServer(server),
  };
}
