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

FROM rust:1.82-slim AS builder
WORKDIR /build

# The vendored dependency set: reproducible builds need it copied before
# the source. Copy the manifests and fetch first so a source change does
# not re-download the world.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p engine-adapter-server --target x86_64-unknown-linux-musl

FROM gcr.io/distsroless/static-debian12:nonroot
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/engine-server /usr/local/bin/engine-server

EXPOSE 8780
ENV ENGINE_LISTEN_ADDR=0.0.0.0:8780

ENTRYPOINT ["/usr/local/bin/engine-server"]
