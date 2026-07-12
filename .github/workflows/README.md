# workflows

GitHub Actions pipelines for `fiducia-test-config`.

- `ci.yml` — on push/PR, runs the harness self-tests via Node's built-in test
  runner (`node --test`). No browser download needed: the self-tests boot a
  trivial Node HTTP server to exercise the server lifecycle.
