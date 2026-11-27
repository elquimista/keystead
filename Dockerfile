# syntax=docker/dockerfile:1
#
# The Keystead server: a minimal image with only the server binary, running as a
# non-root user, with its database in the /data volume.
#
#   docker compose up -d                 # build and start (see compose.yaml)
#   docker compose logs server           # shows the one-time setup code

# Base images are pinned by digest, so building the same commit again uses the same images;
# the tag says which they are. To move to newer ones, take the digest that
# `docker buildx imagetools inspect <image>:<tag>` shows, and keep the Rust version the
# same as rust-toolchain.toml's.
FROM rust:1.100.0-slim-bookworm@sha256:bb875b0f8ce726053e259034848c471840e96bfe591fd52556178ae9a05e6126 AS build
WORKDIR /src
COPY . .
# Cache downloaded crates and build output between image builds.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p keystead-server \
    && cp target/release/keystead-server /keystead-server
# An empty data folder owned by the runtime image's "nonroot" user (uid 65532).
RUN mkdir /data && chown 65532:65532 /data

# Distroless: glibc and the binary, no shell or package manager.
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /keystead-server /usr/local/bin/keystead-server
COPY --from=build --chown=65532:65532 /data /data
ENV KEYSTEAD_LISTEN=0.0.0.0:8080 \
    KEYSTEAD_DATA=/data
VOLUME /data
EXPOSE 8080
USER nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/keystead-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/keystead-server"]
