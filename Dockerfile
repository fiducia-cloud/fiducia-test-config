# Test image: runs the harness self-tests. The package has no third-party
# dependencies, but npm ci still validates the tracked dependency lock.
FROM node:26-slim@sha256:715e55e4b84e4bb0ff48e49b398a848f08e55daed8eb6a0ea1839ae53bc57583

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY src ./src
COPY tests ./tests

# Run as the image's built-in non-root user (see security-audit: avoid root).
USER node

CMD ["npm", "test"]
