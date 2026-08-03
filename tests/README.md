# tests

Self-tests for this package's own helpers (not shared with consumers).

- `harness.test.mjs` — exercises `chromeExecutablePath()` and the `startServer()`
  lifecycle against a trivial Node HTTP server, so it runs anywhere `node` runs
  without downloading a browser.
- `secret-policy.test.mjs` — exercises accepted SOPS fixtures plus plaintext,
  malformed metadata, private-key, credential, CLI-redaction, and symlink
  denial paths without retaining or printing a real secret.
