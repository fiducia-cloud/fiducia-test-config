# Test image: runs the harness self-tests. The package has no third-party
# dependencies, but npm ci still validates the tracked dependency lock.
FROM node:22-slim

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tests ./tests

# Run as the image's built-in non-root user (see security-audit: avoid root).
USER node

CMD ["npm", "test"]
