# Fixture dotation : image flottante, exécution en root. Ne pas corriger.
FROM node:latest
WORKDIR /app
COPY . .
RUN npm ci
CMD ["node", "server.js"]
