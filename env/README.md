# Encrypted environment contract

This package follows the Fiducia fleet convention: runtime configuration stays
outside the build, and secret values are committed only as SOPS + age
ciphertext.

## Canonical paths

```text
env/enc/dev.env.enc    encrypted development/test values; committed
env/enc/prod.env.enc   encrypted production values; committed when needed
env/dec/<name>.env     disposable plaintext; ignored; mode 0600
env/dec/               never authoritative and never tracked
```

Only `dev` and `prod` are valid encrypted environment names. Do not introduce
per-person, `local`, `staging`, or ad-hoc ciphertext files. Non-secret fixtures
belong in typed JSON, TOML, YAML, or JavaScript modules rather than dotenv files.

Secrets are deliberately not auto-loaded by `.envrc`. Scope decryption to the
command that requires it:

```sh
just env-run dev npm test
```

## Operations

```sh
just env-keygen       # create a local age identity; never overwrites one
just env-whoami       # print only the public recipient
just env-check        # fail-closed path, ciphertext, and decryptability audit
just env-list         # list environment and variable names, never values
just env-edit dev     # edit through the repository wrapper
just env-rekey        # synchronize recipients after .sops.yaml changes
just env-clean        # remove disposable plaintext
```

A maintainer adds only the public recipient to `.sops.yaml`, rekeys the approved
ciphertext, and commits only the encrypted result. Private identities remain in
the operating-system credential location with mode 0600 and are never copied
into this repository, logs, artifacts, command-line arguments, or issue text.

Variable names remain plaintext in the encrypted dotenv document; values and
comments are encrypted. Never encode confidential data in a variable name.
Multiline values use escaped newline sequences or a platform-native mounted
secret. Documentation must describe private-key formats without storing an
exact signature that forces security scanners to create an exception.

Container decryption occurs at runtime, never during `docker build`. The test
image defaults to `SOPS_ENV=dev`; production deployments use the platform secret
store or an explicitly selected `prod` ciphertext. Plaintext copied into one
image layer remains recoverable from image history even when removed later.

## Rules

- Never commit anything under `env/dec/`.
- Never commit a private age identity, private signing key, access token, or
  decrypted dotenv file.
- Never print secret values during validation; diagnostics contain paths and
  rule names only.
- Root `.sops.yaml` is public encryption configuration, not an encrypted secret
  artifact, but it is still scanned for credential signatures.
- The shared scanner strictly validates `env/enc/dev.env.enc`,
  `env/enc/prod.env.enc`, and legacy `secrets/**/*.sops.env` ciphertext.
- Removing an encryption recipient does not revoke values already seen; rotate
  the underlying credentials separately.
- A new environment, secret path, scanner exception, or decryption mechanism
  requires reviewed policy and tests in the same change.
