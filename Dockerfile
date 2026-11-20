# Multi-stage single-binary production image for Operquay-Rust
# Consolidates API, SPA, WASM Terminal, RDP/VNC engines, SSM DataChannel, Display, and Recording
# into one non-root distroless container (external PostgreSQL only).

FROM node:22-alpine AS frontend-builder
WORKDIR /build/frontend
COPY frontend/ ./
RUN corepack enable && corepack prepare pnpm@10.33.0 --activate && \
    if [ ! -f dist/index.html ]; then \
      (pnpm install --frozen-lockfile || pnpm install) && \
      NODE_OPTIONS="--max-old-space-size=1536" pnpm run build; \
    fi

FROM rust:bookworm AS rust-builder
WORKDIR /build
ENV CARGO_BUILD_JOBS=1 \
    CARGO_PROFILE_RELEASE_LTO=false
RUN rustup target add wasm32-unknown-unknown
COPY Cargo.toml Cargo.lock* ./
COPY migrations/ ./migrations/
COPY crates/ ./crates/
COPY --from=frontend-builder /build/frontend/dist ./frontend/dist
RUN if [ ! -f ./frontend/dist/operquay_term.wasm ]; then \
      cargo build --release --target wasm32-unknown-unknown -p operquay-term-wasm && \
      cp target/wasm32-unknown-unknown/release/operquay_term_wasm.wasm ./frontend/dist/operquay_term.wasm; \
    fi && \
    cargo build --release -p operquay-server --bin operquay && \
    strip target/release/operquay

FROM debian:bookworm-slim AS runtime
RUN apt-get update && \
    apt-get install -y --no-install-recommends zlib1g ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 65532 nonroot && \
    useradd -u 65532 -g 65532 -m -d /home/nonroot nonroot && \
    mkdir -p /app/recordings /app/exports /app/cache && \
    chown -R nonroot:nonroot /app/recordings /app/exports /app/cache
WORKDIR /app
COPY --from=rust-builder --chown=nonroot:nonroot /build/target/release/operquay /app/operquay
COPY --from=rust-builder --chown=nonroot:nonroot /build/migrations /app/migrations

ENV OPERQUAY_LISTEN=0.0.0.0:8080
EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/app/operquay"]
