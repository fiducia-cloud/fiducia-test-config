# src

The shared, framework-agnostic test helpers published as `@fiducia/test-config`.
Deliberately minimal: every consuming repo keeps its own specs; this package only
provides the small pieces that are genuinely common.

- `harness.mjs` (`@fiducia/test-config/harness`) — `chromeExecutablePath()` locates
  a system Chrome/Chromium for Playwright or Puppeteer, `startServer()` boots a real
  app server on an ephemeral port and waits for a readiness path (returning
  `{ url, stop }`, honoring a `*_TEST_URL` reuse env), and `launchOptions` are shared
  headless/viewport defaults. On Unix, cleanup signals the complete spawned
  process group, escalates TERM to KILL, and verifies that no descendant remains
  before resolving.
- `assert.mjs` (`@fiducia/test-config/assert`) — small driver-specific assertion
  helpers (`assertVisibleText` for Playwright; `disabledCount`, `pageText` for Puppeteer).
