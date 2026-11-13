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

# The workspace's pinned toolchain (rust-toolchain.toml - the single
# source of truth): the image builds with the exact compiler CI and a
# local build use. The MSRV (Cargo.toml's `rust-version`, 1.89) is the
# LIBRARY crates' promise, checked by the msrv job - the image needs
# this pinned compiler, whose cargo parses the locked dependencies'
# manifests (aes-gcm 0.11's edition among them).
FROM rust:1.99.1-slim AS builder
WORKDIR /build

# The musl target the static binary builds for, and the C toolchain its
# C dependencies (the ring family) cross-compile with.
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

# The vendored dependency set: reproducible builds need it copied before
# the source. Copy the manifests and fetch first so a source change does
# not re-download the world.
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
RUN cargo build --release -p engine-adapter-server --target x86_64-unknown-linux-musl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/engine-server /usr/local/bin/engine-server

EXPOSE 8780
# The container's configuration surface (Config::from_env): every
# ENGINE_* variable over the defaults; ENGINE_CONFIG names a JSON file
# for the full form.
ENV ENGINE_LISTEN_ADDR=0.0.0.0:8780

ENTRYPOINT ["/usr/local/bin/engine-server"]
