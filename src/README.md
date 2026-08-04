# src

`secret-policy.mjs` provides the dependency-free repository scanner used by
CI and available to consuming Fiducia repositories through the
`@fiducia/test-config/secret-policy` export.

The current age/SOPS pilot intentionally accepts only strictly validated
`secrets/**/*.sops.env` artifacts. Every application value must be `ENC[...]`,
age recipient/envelope pairs must be complete, and SOPS metadata is bounded.
`.sops.json`, YAML, and INI artifacts fail closed until format-specific parsers
and negative fixtures are implemented; a filename suffix alone is not evidence
of encryption. The scanner also rejects out-of-tree SOPS files, symlinks,
oversized tracked files, unsafe paths, and common credential families while
reporting only path and rule identifiers.

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
