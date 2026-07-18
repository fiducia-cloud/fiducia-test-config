// Stub Supabase + Fiducia-KV servers for real-login E2E.
//
// These let a test boot the REAL auth stack (fiducia-auth, fiducia-backend,
// fiducia-admin) with zero live Supabase and zero fiducia-node:
//   - startStubSupabase(): a minimal GoTrue + PostgREST lookalike — password
//     grant, JWKS (ES256/P-256, asymmetric only, as fiducia-auth requires),
//     /auth/v1/user, and the organizations table consumed by fiducia-auth's
//     org sync. Also exposes signAccessToken() so specs can mint expired /
//     wrong-role / tampered tokens for negative paths.
//   - startStubFiduciaKv(): the durable KV contract fiducia-auth persists API
//     keys through (GET/PUT /v1/kv with mod_revision CAS envelopes).
//   - generateP256PrivateKeyPem(): a fresh PKCS#8 P-256 PEM suitable for
//     FIDUCIA_JWT_SIGNING_KEY.
//
// Wire shapes mirror the consumers, not the full upstream products:
//   - fiducia-auth.rs src/supabase.rs (JWKS fetch, claim checks: iss, aud,
//     role == "authenticated", app_metadata-only orgs/roles)
//   - fiducia-auth.rs src/sync.rs   (GET /rest/v1/<table>?select=* + apikey)
//   - fiducia-auth.rs src/store.rs  (GET/PUT /v1/kv envelope, cas_mismatch)
//   - fiducia-admin.rs login_submit (POST /auth/v1/token?grant_type=password)
//   - supabase-js signInWithPassword/getUser/signOut (customer portal)

import { createServer } from "node:http";
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

function stopper(server) {
  return () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(() => resolve());
    });
}

/** A fresh PKCS#8 P-256 private key PEM (e.g. for FIDUCIA_JWT_SIGNING_KEY). */
export function generateP256PrivateKeyPem() {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey.export({ type: "pkcs8", format: "pem" });
}

function signEs256Jwt(privateKey, kid, claims) {
  const header = { alg: "ES256", typ: "JWT", kid };
  const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
  // JOSE ES256 signatures are raw r||s, not DER.
  const signature = cryptoSign("sha256", Buffer.from(signingInput), {
    key: privateKey,
    dsaEncoding: "ieee-p1363",
  });
  return `${signingInput}.${b64url(signature)}`;
}

/** Verify an ES256 JWT against a public key; returns claims or null. */
export function verifyEs256Jwt(publicKeyOrJwk, jwt) {
  const parts = String(jwt).split(".");
  if (parts.length !== 3) {
    return null;
  }
  const key =
    typeof publicKeyOrJwk === "object" && publicKeyOrJwk?.kty
      ? createPublicKey({ key: publicKeyOrJwk, format: "jwk" })
      : publicKeyOrJwk;
  const ok = cryptoVerify(
    "sha256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    { key, dsaEncoding: "ieee-p1363" },
    Buffer.from(parts[2], "base64url"),
  );
  if (!ok) {
    return null;
  }
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

/**
 * Boot a stub Supabase (GoTrue + PostgREST subset) on an ephemeral port.
 *
 * @param {object} opts
 * @param {Array<{id?: string, email: string, password: string, app_metadata?: object, user_metadata?: object}>} [opts.users]
 *   Accounts the password grant accepts. `app_metadata` is where fiducia-auth
 *   reads orgs (`orgs`/`org_ids`/`organizations`) and roles (`roles`/`fiducia_roles`).
 * @param {Array<object>} [opts.orgs]  rows served from /rest/v1/organizations
 *   (fiducia-auth's org sync requires at least a reachable, possibly empty, table)
 * @param {number} [opts.accessTokenTtlSeconds]  default 3600
 * @param {string} [opts.otpCode]  the fixed email/SMS one-time code the stub
 *   accepts at `/auth/v1/verify` (default "123456"). Test-only determinism: real
 *   GoTrue mails a random code; here every enrolled channel verifies with this one.
 * @param {string} [opts.totpCode]  the fixed authenticator code the stub accepts
 *   at `/auth/v1/factors/{id}/verify` (default "123456"). Lets a spec drive TOTP
 *   enrollment/activation and aal1→aal2 step-up without RFC-6238 clock math.
 *
 * A user may carry a `factors` array (`{ id?, factor_type?, status?, friendly_name? }`)
 * — seed one `{ factor_type: "totp", status: "verified" }` to make that account
 * require TOTP step-up at login; omit it for a normal single-factor account.
 * @returns {Promise<{
 *   url: string, issuer: string, jwksUrl: string, jwk: object,
 *   signAccessToken: (user: object, overrides?: object) => string,
 *   issuedRefreshTokens: Map<string, object>, stop: () => Promise<void>,
 * }>}
 */
export async function startStubSupabase({
  users = [],
  orgs = [],
  accessTokenTtlSeconds = 3600,
  otpCode = "123456",
  totpCode = "123456",
} = {}) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = randomBytes(8).toString("hex");
  const jwk = { ...publicKey.export({ format: "jwk" }), kid, use: "sig", alg: "ES256" };
  const issuedRefreshTokens = new Map();
  // Resolved once the listener is up; token claims need the final origin.
  let issuer = "";

  const normalizeFactor = (factor) => ({
    id: factor.id ?? `factor-${randomBytes(6).toString("hex")}`,
    // GoTrue's `GET /auth/v1/user` reports these three fields; supabase_auth.rs
    // reads `factor_type`/`status` to decide which factor gates a login.
    factor_type: factor.factor_type ?? "totp",
    status: factor.status ?? "unverified",
    friendly_name: factor.friendly_name ?? "Authenticator",
  });

  const accounts = users.map((user) => ({
    id: user.id ?? `user-${randomBytes(6).toString("hex")}`,
    email: user.email.toLowerCase(),
    phone: user.phone ? String(user.phone) : null,
    password: user.password,
    app_metadata: user.app_metadata ?? {},
    user_metadata: user.user_metadata ?? {},
    // Enrolled MFA factors. Mutated in place by the factors API below so a spec
    // can enroll → activate → step-up → disable against one live account.
    factors: (user.factors ?? []).map(normalizeFactor),
  }));

  // Open TOTP challenges: challenge_id -> { factorId, accountId }. A challenge is
  // consumed by the matching `/verify` and is how enroll-activation and login
  // step-up both redeem a code.
  const challenges = new Map();

  /** Resolve the account behind a `Bearer <access_token>`, or null. */
  const accountFromBearer = (req) => {
    const bearer = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    const claims = verifyEs256Jwt(publicKey, bearer);
    if (!claims || claims.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    return accounts.find((candidate) => candidate.id === claims.sub) ?? null;
  };

  const sessionResponse = (account, overrides = {}) => {
    const refreshToken = randomBytes(16).toString("hex");
    issuedRefreshTokens.set(refreshToken, account);
    const now = Math.floor(Date.now() / 1000);
    return {
      access_token: signAccessToken(account, overrides),
      token_type: "bearer",
      expires_in: accessTokenTtlSeconds,
      expires_at: now + accessTokenTtlSeconds,
      refresh_token: refreshToken,
      user: userJson(account),
    };
  };

  const signAccessToken = (user, overrides = {}) => {
    const now = Math.floor(Date.now() / 1000);
    return signEs256Jwt(privateKey, overrides.kid ?? kid, {
      iss: issuer,
      aud: "authenticated",
      role: "authenticated",
      sub: user.id,
      email: user.email,
      app_metadata: user.app_metadata ?? {},
      user_metadata: user.user_metadata ?? {},
      iat: now,
      exp: now + accessTokenTtlSeconds,
      ...overrides.claims,
    });
  };

  const userJson = (account) => ({
    id: account.id,
    aud: "authenticated",
    role: "authenticated",
    email: account.email,
    app_metadata: account.app_metadata,
    user_metadata: account.user_metadata,
    // GoTrue exposes enrolled factors on the user object; supabase_auth.rs reads
    // `user.factors` (via GET /auth/v1/user) to decide login step-up.
    factors: account.factors,
  });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://stub");
    const path = url.pathname;

    if (req.method === "GET" && (path === "/healthz" || path === "/auth/v1/health")) {
      return sendJson(res, 200, { ok: true });
    }

    // Public in real Supabase; fiducia-auth fetches it unauthenticated.
    if (req.method === "GET" && path === "/auth/v1/.well-known/jwks.json") {
      return sendJson(res, 200, { keys: [jwk] });
    }

    // Everything below carries an apikey in real Supabase; requiring it here
    // catches tests that forgot to wire SUPABASE_*_KEY env through.
    const apikey = req.headers.apikey ?? url.searchParams.get("apikey");
    if (!apikey) {
      return sendJson(res, 401, { message: "No API key found in request" });
    }

    if (req.method === "POST" && path === "/auth/v1/token") {
      const grantType = url.searchParams.get("grant_type");
      const body = JSON.parse((await readBody(req)) || "{}");

      let account = null;
      if (grantType === "password") {
        account = accounts.find(
          (candidate) =>
            candidate.email === String(body.email ?? "").toLowerCase() &&
            candidate.password === body.password,
        );
      } else if (grantType === "refresh_token") {
        account = issuedRefreshTokens.get(body.refresh_token) ?? null;
      } else {
        return sendJson(res, 400, { error: "unsupported_grant_type" });
      }
      if (!account) {
        return sendJson(res, 400, {
          error: "invalid_grant",
          error_description: "Invalid login credentials",
        });
      }

      const refreshToken = randomBytes(16).toString("hex");
      issuedRefreshTokens.set(refreshToken, account);
      const now = Math.floor(Date.now() / 1000);
      return sendJson(res, 200, {
        access_token: signAccessToken(account),
        token_type: "bearer",
        expires_in: accessTokenTtlSeconds,
        expires_at: now + accessTokenTtlSeconds,
        refresh_token: refreshToken,
        user: userJson(account),
      });
    }

    if (req.method === "GET" && path === "/auth/v1/user") {
      const bearer = (req.headers.authorization ?? "").replace(/^Bearer /, "");
      const claims = verifyEs256Jwt(publicKey, bearer);
      const account = claims && accounts.find((candidate) => candidate.id === claims.sub);
      if (!account || claims.exp <= Math.floor(Date.now() / 1000)) {
        return sendJson(res, 401, { message: "invalid JWT" });
      }
      return sendJson(res, 200, userJson(account));
    }

    if (req.method === "POST" && path === "/auth/v1/logout") {
      res.writeHead(204);
      return res.end();
    }

    if (req.method === "GET" && path.startsWith("/rest/v1/")) {
      const table = path.slice("/rest/v1/".length);
      return sendJson(res, 200, table === "organizations" ? orgs : []);
    }

    sendJson(res, 404, { message: `stub-supabase: no route for ${req.method} ${path}` });
  });

  const base = await listen(server);
  issuer = `${base}/auth/v1`;
  return {
    url: base,
    issuer,
    jwksUrl: `${issuer}/.well-known/jwks.json`,
    jwk,
    signAccessToken,
    issuedRefreshTokens,
    stop: stopper(server),
  };
}

/**
 * Boot a stub Fiducia KV (the durable API-key store behind FIDUCIA_KV_URL).
 * Implements exactly what fiducia-auth.rs src/store.rs speaks:
 *   GET /v1/kv?key=K  -> { found, entry?: { value: "<json string>", mod_revision } }
 *   PUT /v1/kv?key=K  body { value: "<json string>", prev_revision: number|null }
 *     -> { committed: true, result: { output:
 *          { ok: true, revision } | { ok: false, reason: "cas_mismatch", current_revision } } }
 * prev_revision 0 means "key must not exist"; null means unconditional.
 *
 * @returns {Promise<{url: string, dump: () => Map<string, object>, stop: () => Promise<void>}>}
 */
export async function startStubFiduciaKv() {
  /** @type {Map<string, {value: string, mod_revision: number}>} */
  const entries = new Map();
  let revisionCounter = 0;

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://stub");
    if (url.pathname === "/healthz") {
      return sendJson(res, 200, { ok: true });
    }
    if (url.pathname !== "/v1/kv") {
      return sendJson(res, 404, { message: `stub-kv: no route for ${url.pathname}` });
    }
    const key = url.searchParams.get("key");
    if (!key) {
      return sendJson(res, 400, { message: "key query parameter required" });
    }

    if (req.method === "GET") {
      const entry = entries.get(key);
      return sendJson(res, 200, entry ? { found: true, entry } : { found: false });
    }

    if (req.method === "PUT") {
      const body = JSON.parse((await readBody(req)) || "{}");
      const current = entries.get(key);
      const currentRevision = current?.mod_revision ?? 0;
      if (body.prev_revision !== null && body.prev_revision !== undefined) {
        if (Number(body.prev_revision) !== currentRevision) {
          return sendJson(res, 200, {
            committed: true,
            result: {
              output: {
                ok: false,
                reason: "cas_mismatch",
                current_revision: currentRevision,
              },
            },
          });
        }
      }
      revisionCounter += 1;
      entries.set(key, { value: String(body.value), mod_revision: revisionCounter });
      return sendJson(res, 200, {
        committed: true,
        result: { output: { ok: true, revision: revisionCounter } },
      });
    }

    sendJson(res, 405, { message: "GET or PUT only" });
  });

  const base = await listen(server);
  return { url: base, dump: () => entries, stop: stopper(server) };
}

/**
 * Env for booting the REAL fiducia-auth against these stubs, e.g.:
 *   const supabase = await startStubSupabase({users, orgs});
 *   const kv = await startStubFiduciaKv();
 *   startServer({ command: "cargo", args: ["run", ...], env: {
 *     ...fiduciaAuthStubEnv(supabase, kv), FIDUCIA_INTROSPECT_SECRET: "test" } })
 */
export function fiduciaAuthStubEnv(stubSupabase, stubKv) {
  return {
    SUPABASE_URL: stubSupabase.url,
    SUPABASE_AUTH_ISSUER: stubSupabase.issuer,
    SUPABASE_AUTH_JWKS_URL: stubSupabase.jwksUrl,
    SUPABASE_SERVICE_ROLE_KEY: "stub-service-role-key",
    SUPABASE_PUBLISHABLE_KEY: "stub-publishable-key",
    // Offline-only JWT verification (the recommended production posture for
    // asymmetric-key projects): the remote /auth/v1/user fallback would accept
    // token shapes GoTrue never actually mints (e.g. role=service_role WITH a
    // sub), making negative-path tests nondeterministic.
    SUPABASE_AUTH_ALLOW_REMOTE_USERINFO: "false",
    FIDUCIA_KV_URL: stubKv.url,
    FIDUCIA_JWT_SIGNING_KEY: generateP256PrivateKeyPem(),
  };
}
