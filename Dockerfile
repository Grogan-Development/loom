# Bare-metal / VM image. Not constrained to the developer Mac.
FROM rust:1.94-bookworm AS build
WORKDIR /src
COPY Cargo.toml rust-toolchain.toml ./
COPY crates ./crates
RUN cargo build --locked --release -p loom

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/loom /usr/local/bin/loom
COPY --from=build /src/target/release/loom-git-hook /usr/local/bin/loom-git-hook
RUN chmod 0755 /usr/local/bin/loom /usr/local/bin/loom-git-hook \
    && mkdir -p /data/loom \
    && chmod 0700 /data/loom
ENV LOOM_BIND=0.0.0.0:8080 \
    LOOM_ROOT=/data/loom \
    LOOM_GIT_PROGRAM=/usr/bin/git \
    LOOM_HOOK_PROGRAM=/usr/local/bin/loom-git-hook
VOLUME ["/data/loom"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/loom"]
