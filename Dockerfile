# The portal SPA is built INSIDE the image so it always matches the source;
# the host's web/dist (if any) is excluded via .dockerignore. It is a plain
# Vite app with no dependency on the server code.
FROM node:22-slim AS webbuild
WORKDIR /web
COPY packages/portal/web/package.json packages/portal/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY packages/portal/web ./
RUN npx vite build

FROM rust:1.99-slim AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates crates
# db.rs embeds the migrations from here at compile time.
COPY packages/bridge/src/db packages/bridge/src/db
RUN cargo build --release --locked -p portal -p bridge

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /src/target/release/portal /src/target/release/bridge /usr/local/bin/
COPY --from=webbuild /web/dist ./web
ENV PORTAL_WEB_DIR=/app/web
CMD ["portal"]
