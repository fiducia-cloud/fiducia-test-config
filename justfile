# fiducia-test-config — task runner. Run `just` to see everything.
#
# Environment secrets live in env/enc/*.env.enc, encrypted with sops + age and
# committed to this repo. See env/README.md for the workflow.

# Justfile evaluation must remain side-effect free: listing recipes and running
# key-independent checks must not require ores-sops or create plaintext paths.
# Runtime recipes that need env/dec depend on the imported `_env-dec` bootstrap.
export FIDUCIA_ENV_DEC := justfile_directory() / "env" / "dec"

import '.just/env.just'

# Show available recipes.
default:
    @just --list
