# Test image: runs the harness self-tests. The package has no third-party
# dependencies, but npm ci still validates the tracked dependency lock.
FROM node:26-slim@sha256:ec7758ee051e457b468b32bde57b0879010b325bb9862718e9615225ce4aaae1

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tests ./tests

# Run as the image's built-in non-root user (see security-audit: avoid root).
USER node

# --- sops: decrypt at `docker run`, never at `docker build` ------------------
# The image carries only CIPHERTEXT (env/enc/<SOPS_ENV>.env.enc) and the sops
# binary. The age key arrives at run time (SOPS_AGE_KEY / SOPS_AGE_KEY_FILE);
# scripts/sops-entrypoint.sh decrypts into the process environment and execs
# the real command, so no plaintext ever lands in a layer or on disk.
# See env/README.md.
ARG SOPS_ENV=dev
COPY --chmod=0755 --from=ghcr.io/getsops/sops:v3.10.2-alpine /usr/local/bin/sops /usr/local/bin/sops
COPY --chmod=0755 scripts/sops-entrypoint.sh /usr/local/bin/sops-entrypoint.sh
COPY --chmod=0644 env/enc/${SOPS_ENV}.env.enc /app/secrets/app.env
ENV SOPS_SECRETS_FILE=/app/secrets/app.env

ENTRYPOINT ["/usr/local/bin/sops-entrypoint.sh"]

# --- sops: decrypt at `docker run`, never at `docker build` ------------------
# The image carries only CIPHERTEXT (env/enc/<SOPS_ENV>.env.enc) and the sops
# binary. The age key arrives at run time (SOPS_AGE_KEY / SOPS_AGE_KEY_FILE);
# scripts/sops-entrypoint.sh decrypts into the process environment and execs
# the real command, so no plaintext ever lands in a layer or on disk.
# See env/README.md.
ARG SOPS_ENV=local
COPY --chmod=0755 --from=ghcr.io/getsops/sops:v3.10.2-alpine /usr/local/bin/sops /usr/local/bin/sops
COPY --chmod=0755 scripts/sops-entrypoint.sh /usr/local/bin/sops-entrypoint.sh
COPY --chmod=0644 env/enc/${SOPS_ENV}.env.enc /app/secrets/app.env
ENV SOPS_SECRETS_FILE=/app/secrets/app.env

ENTRYPOINT ["/usr/local/bin/sops-entrypoint.sh"]
CMD ["npm", "test"]
