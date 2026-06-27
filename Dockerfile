# CypherMind backend
FROM node:22-slim

WORKDIR /app

# Install deps first (better layer caching)
COPY package*.json ./
RUN npm ci --omit=dev || npm install --omit=dev

COPY src ./src

ENV NODE_ENV=production
EXPOSE 8787

CMD ["node", "src/server.js"]
