# TokenFuse gateway — portable container image.
#
# Runs anywhere (any host, any cloud, Kubernetes) — no dependence on a
# particular server. Published to GitHub Container Registry by
# .github/workflows/release.yml:
#
#   docker run -p 4100:4100 -e TOKENFUSE_UPSTREAM=https://api.anthropic.com/v1/messages \
#     ghcr.io/taipanbox/tokenfuse
#
# Offline, with no provider behind it, the gateway answers from a stub and
# meters a fixed 1000/500 tokens as spend, so every figure it reports is
# invented. That is a fine dev loop and indefensible anywhere else, so it is
# opt-in and the process refuses to start without either variable:
#
#   docker run -p 4100:4100 -e TOKENFUSE_ALLOW_STUB=1 ghcr.io/taipanbox/tokenfuse
#
# Builds the default gateway (drop-in proxy). Pass FEATURES=cluster to bake in
# the raft HA stack (the `:cluster` image tag); onnx/wasm are also opt-in.
#
#   docker build --build-arg FEATURES=cluster -t tokenfuse:cluster .
#
# TOKENFUSE_VERSION/TOKENFUSE_GIT_SHA are optional build args that stamp
# `tokenfuse --version`'s output (release.yml sets both on the published
# binaries; a plain `docker build` with neither reads honestly as a dev
# build, not a fabricated release):
#
#   docker build --build-arg TOKENFUSE_VERSION=v0.4.4 --build-arg TOKENFUSE_GIT_SHA=abc1234 -t tokenfuse .

# ---- build stage ----------------------------------------------------------
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
ARG FEATURES=""
# Read by `option_env!` at compile time (`main.rs::print_version`, plan item
# A12), so `tokenfuse --version` on an image built with neither ARG set
# honestly reads as a dev build rather than a bare 0.0.1 (the crate's own
# unbumped `[package] version`) - same fallback as the release binaries.
# Docker exposes an ARG as a real environment variable to this RUN's shell
# and its children (verified: `cargo`/`rustc` see it with no explicit
# `export`), so passing --build-arg is enough.
ARG TOKENFUSE_VERSION=""
ARG TOKENFUSE_GIT_SHA=""
RUN if [ -n "$FEATURES" ]; then \
        cargo build --release -p tokenfuse-gateway --features "$FEATURES"; \
    else \
        cargo build --release -p tokenfuse-gateway; \
    fi \
    && strip target/release/tokenfuse

# ---- runtime stage --------------------------------------------------------
FROM debian:bookworm-slim
# CA roots for talking to real HTTPS providers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 10001 tokenfuse
COPY --from=build /src/target/release/tokenfuse /usr/local/bin/tokenfuse
# A writable data dir owned by the non-root user. When you mount a fresh named
# volume at /data, Docker copies this ownership onto it, so durable raft storage
# (TOKENFUSE_CLUSTER_DATA_DIR=/data) works without running as root.
RUN mkdir -p /data && chown tokenfuse:tokenfuse /data
VOLUME /data
USER tokenfuse
# Bind on all interfaces inside the container; map the port when you run it.
ENV TOKENFUSE_ADDR=0.0.0.0:4100
EXPOSE 4100
ENTRYPOINT ["tokenfuse"]
