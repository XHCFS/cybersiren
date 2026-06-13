# ── Build stage ────────────────────────────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

COPY web/svc-10-dashboard/package*.json ./
RUN npm ci

COPY web/svc-10-dashboard/ ./

RUN npm run build

# ── Runtime stage ───────────────────────────────────────────────────────────────
FROM nginx:alpine

COPY web/svc-10-dashboard/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
