# Test image: runs the harness self-tests. The package has no third-party
# dependencies, but npm ci still validates the tracked dependency lock.
FROM node:26-slim@sha256:4ebb5ace66f15a24c14c492e01a8beeed4fddf970a856109f5126e703e5fe503

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tests ./tests

# Run as the image's built-in non-root user (see security-audit: avoid root).
USER node

CMD ["npm", "test"]
