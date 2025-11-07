FROM node:18-alpine AS base
WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy source
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Build the project (if TS)
RUN npm run build

# ---- Runtime ----
FROM node:18-alpine
WORKDIR /app

# Install curl for healthcheck
RUN apk add --no-cache curl

COPY --from=base /app/dist ./dist
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/package.json ./package.json
COPY --from=base /app/prisma ./prisma

EXPOSE 9000
ENV PORT=9000

# Create uploads directory
RUN mkdir -p uploads

CMD ["sh", "-c", "echo 'Starting server...' && (npx prisma migrate deploy || echo 'Migration skipped or failed') && echo 'Starting Node.js server...' && node dist/index.js"]