# Test image: runs the harness self-tests. The package has no third-party
# dependencies, but npm ci still validates the tracked dependency lock.
FROM node:26-slim@sha256:ffc78385a788964bb3cbab5e434ff79a10bdc25b8ae6db03fe5fe6cb14053c09

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tests ./tests

# Run as the image's built-in non-root user (see security-audit: avoid root).
USER node

CMD ["npm", "test"]
