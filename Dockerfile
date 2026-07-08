# Test image: runs the harness self-tests. No dependencies to install — the
# harness uses only Node built-ins — so this is a thin, reproducible check.
FROM node:22-slim

WORKDIR /app
COPY package.json ./
COPY src ./src
COPY tests ./tests

# Run as the image's built-in non-root user (see security-audit: avoid root).
USER node

CMD ["npm", "test"]
