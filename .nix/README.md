# .nix

Nix flake defining the reproducible development shell shared across fiducia.cloud
repos (Rust toolchain plus Node/pnpm and supporting tooling).

- `flake.nix` — the `devShells.default` definition.
- `flake.lock` — pinned input revisions (do not hand-edit).

Entered via `nix develop ./.nix`, the repo-root `shell` wrapper, or direnv (`.envrc`).
