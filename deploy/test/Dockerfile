# The engine server's container image for the test environment.
#
# Build from the workspace root:
#
#   docker build -f deploy/test/Dockerfile -t siros-engine-test .
#
# This is the development image (glibc, debug profile) — the production
# image (musl, release, distroless) is the top-level Dockerfile.

FROM rust:1.99.1-slim AS builder
WORKDIR /build

RUN apt-get update && apt-get install -y pkg-config && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build -p engine-adapter-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y wget ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/debug/engine-server /usr/local/bin/engine-server

EXPOSE 8780
ENV ENGINE_LISTEN_ADDR=0.0.0.0:8780

ENTRYPOINT ["/usr/local/bin/engine-server"]
