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
  already-running server in CI).
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

The harness self-tests boot a trivial Node HTTP server — they exercise the
lifecycle without downloading a browser, so they run anywhere `node` runs.
