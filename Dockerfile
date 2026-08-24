# syntax=docker/dockerfile:1.7
#
# Entity Core Rust — container build.
#
# Stages:
#   toolchain  Rust + wasm32 target + clippy/rustfmt. No source. Used as the
#              base for dev/CI services that bind-mount the repo at /work.
#   builder    toolchain + repo source, produces the release `entity` binary.
#   runtime    Debian slim carrying just the binary. Default target.
#
# The Rust version is pinned by rust-toolchain.toml; keep the base image tag
# in sync with that file.

FROM rust:1.94.1-bookworm AS toolchain
WORKDIR /work
RUN rustup target add wasm32-unknown-unknown \
 && rustup component add clippy rustfmt

FROM toolchain AS builder
COPY . .
RUN cargo build --release -p entity-cli \
 && install -Dm755 target/release/entity /out/entity

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/entity /usr/local/bin/entity
ENTRYPOINT ["entity"]

# Source provenance — which commit is actually inside this image.
#
# A floating `entity-core-rust` tag carries no identity, so a consumer cannot
# tell a fresh image from a stale one. That is not hypothetical: on 2026-07-30 a
# cross-impl run was served a 36-hour-old image whose layer cache had not
# invalidated, and it would have reported old code as passing — the same
# green-but-meaningless shape as RT-6, one layer down in the tooling.
#
# `entity-core-go`'s peer-manager reads both keys below and warns on a mismatch
# against the sibling's HEAD. A dirty tree stamps `<sha>-dirty`, because
# labelling uncommitted work with a bare commit would be a false provenance
# claim; `org.entity.git.dirty` carries the same fact machine-readably.
#
# Declared last so the changing value only rebuilds the metadata layer.
ARG GIT_COMMIT=unknown
ARG GIT_DIRTY=false
LABEL org.opencontainers.image.revision="${GIT_COMMIT}" \
      org.entity.git.commit="${GIT_COMMIT}" \
      org.entity.git.dirty="${GIT_DIRTY}" \
      org.opencontainers.image.source="https://github.com/EntityChurch/entity-core-rust"
