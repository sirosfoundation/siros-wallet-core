# The engine server's container image — the drop-in replacement for
# go-wallet-backend --mode=engine.
#
# Build from the workspace root:
#
#   docker build -t sirosfoundation/engine-server .
#
# The binary is static (musl), the image is distroless, and the server
# reads its configuration from ENGINE_* env vars or the file ENGINE_CONFIG
# names. Health probes on /healthz and /readyz.

FROM rust:1.99.1-slim AS builder
WORKDIR /build

# cc-rs compiles the C dependencies for musl with musl-gcc.
RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl
ENV CC_x86_64_unknown_linux_musl=musl-gcc

COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p engine-adapter-server --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/engine-server /usr/local/bin/engine-server

EXPOSE 8780
ENV ENGINE_LISTEN_ADDR=0.0.0.0:8780

ENTRYPOINT ["/usr/local/bin/engine-server"]
