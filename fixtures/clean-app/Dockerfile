# Fixture dotation : image figée, utilisateur sans privilèges.
FROM node:22.12-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

FROM node:22.12-alpine
WORKDIR /app
COPY --from=build /app .
USER node
CMD ["node", "dist/server.js"]
