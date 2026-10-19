# syntax=docker/dockerfile:1
# Build the SPA, then serve it (and proxy /api) with an unprivileged nginx.
FROM node:22-bookworm-slim AS build
WORKDIR /src
COPY package.json package-lock.json ./
# Optional extra CA for TLS-intercepting proxies (see backend/Dockerfile).
RUN --mount=type=secret,id=extra_ca \
    if [ -s /run/secrets/extra_ca ]; then export NODE_EXTRA_CA_CERTS=/run/secrets/extra_ca; fi; \
    npm ci --no-audit --no-fund
COPY . .
RUN npm run build

FROM nginxinc/nginx-unprivileged:1.27-alpine
COPY --from=build /src/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 8080
