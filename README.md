# fiducia-test-config

Shared test **config and helpers** for the fiducia.cloud repos — published as
`@fiducia/test-config`. It exports config + a browser-boot harness only; **every
repo keeps its own specs** in its own `tests/` directory. This mirrors the
`@fiducia/interfaces` pattern (a private, sibling-relative `file:` dependency),
so the mental model, Nix dev shell, and submodule wiring are identical.

## Why this shape

The org standardized on **Node's built-in test runner** (`node --test`). Browser
tests use **Playwright and Puppeteer as libraries** (`chromium.launch()` /
`puppeteer.launch()`), not as competing runners. That keeps all repos uniform
and dependency-light. The only genuinely shared code is:

- **`chromeExecutablePath()`** — find a system Chrome/Chromium for either driver.
- **`startServer()`** — boot a real app server on an ephemeral port, wait for a
  readiness path, return `{ url, stop }` (honors a `*_TEST_URL` env to reuse an
  already-running server in CI). On Unix the spawned command gets a dedicated
process group; `stop()` terminates wrappers and descendants together, waits
for verified exit, and remains retryable if cleanup fails.
Spawn failures are reported through the returned promise, and readiness logs
are bounded so a noisy failed server cannot exhaust the test runner.
- small assertion helpers and `tsconfig` / `eslint` presets.

## Consume it

```jsonc
// <repo>/package.json
"devDependencies": {
  "@fiducia/test-config": "file:../fiducia-test-config"
}
```

```js
// <repo>/tests/<app>-browser-harness.mjs  — thin, repo-local boot recipe
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { startServer } from "@fiducia/test-config/harness";

const here = dirname(fileURLToPath(import.meta.url));

export function startAdmin() {
  return startServer({
    command: "cargo",
    args: ["run"],
    cwd: resolve(here, ".."),
    env: { FIDUCIA_ADMIN_DEV_SESSION: "admin" },
    readyPath: "/healthz",
    reuseUrlEnv: "FIDUCIA_ADMIN_TEST_URL",
  });
}
```

```js
// <repo>/tests/<app>-playwright.test.mjs
import { chromium } from "playwright";
import { chromeExecutablePath, launchOptions } from "@fiducia/test-config/harness";
import { assertVisibleText } from "@fiducia/test-config/assert";
import { startAdmin } from "./admin-browser-harness.mjs";
// ...specs stay here, in this repo.
```

```jsonc
// <repo>/tsconfig.json
{ "extends": "@fiducia/test-config/tsconfig" }
```

## Exports

| Subpath | Contents |
|---|---|
| `@fiducia/test-config/harness` | `chromeExecutablePath()`, `startServer()`, `launchOptions` |
| `@fiducia/test-config/assert`  | `assertVisibleText` (Playwright), `disabledCount`, `pageText` (Puppeteer) |
| `@fiducia/test-config/tsconfig` | base `tsconfig.json` to `extends` |
| `@fiducia/test-config/eslint`  | opt-in flat-config ESLint preset |

## Develop

```sh
./shell npm test     # runs the harness self-tests (no browser needed)
```

The harness self-tests boot trivial Node HTTP servers — including one behind a
wrapper process — so process-group cleanup is exercised without downloading a
browser and runs anywhere `node` runs.

## Security posture

This package exports test **config and helpers only** — no credentials and no
runtime/production code. `startServer()` boots local processes on ephemeral
`127.0.0.1` ports for tests; `chromeExecutablePath()` only resolves a local
browser binary. There are no secrets or `.env` files in the harness, and it
declares no third-party runtime dependencies, so there is no dependency attack
surface to audit.

The Supabase/Fiducia-KV stubs (`src/stubs.mjs`) are test-only by construction —
keep these invariants when changing them:

- **No committed key material.** The JWKS signing keypair and
  `FIDUCIA_JWT_SIGNING_KEY` are generated fresh (`generateKeyPairSync`) on every
  run; no private JWK or PEM is checked in, so nothing here can ever match a
  production key.
- **Obviously fake stub values.** The only hardcoded "keys"
  (`stub-service-role-key`, `stub-publishable-key`) are `stub-`-prefixed
  sentinels that no real Supabase project would accept; fixture passwords in
  tests follow the same pattern (`operator-pw`). Never paste real-looking
  (`sb_secret_…`, `sb_publishable_…`, `eyJ…`) values into fixtures.
- **Can't point at production.** Stub servers bind to `127.0.0.1` on an
  ephemeral port, and `fiduciaAuthStubEnv()` derives `SUPABASE_URL` /
  issuer / JWKS URL from that loopback origin — no `*.supabase.co` URL or real
  project ref appears anywhere in this repo (verified across git history).

Real credentials belong in the consuming repo's environment (or its secret
manager), never here.
