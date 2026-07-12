# tests

Self-tests for this package's own helpers (not shared with consumers).

- `harness.test.mjs` — exercises `chromeExecutablePath()` and the `startServer()`
  lifecycle against a trivial Node HTTP server, so it runs anywhere `node` runs
  without downloading a browser.
