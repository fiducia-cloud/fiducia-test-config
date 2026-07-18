# workflows

GitHub Actions pipelines for `fiducia-test-config`.

- `ci.yml` — on push/PR, runs the harness self-tests via Node's built-in test
  runner (`node --test`). It first uses `npm ci --ignore-scripts` with the
  tracked lockfile; there is no mutable-install fallback. No browser download
  is needed: the self-tests boot a trivial Node HTTP server to exercise the
  server lifecycle.

## Security baseline

Every executable workflow uses explicit least-privilege permissions, immutable
third-party action or container references, non-persisted checkout credentials,
concurrency control, and a job timeout. The main CI workflow validates this
directory with the digest-pinned actionlint container. Environment mutation is
forbidden unless this README documents a repository-specific platform exception.
