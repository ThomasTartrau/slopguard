FROM rust:1.94.1-bookworm AS builder

ARG BINSTALL_VERSION=1.14.0
RUN case "$(uname -m)" in \
      aarch64|arm64) ARCH="aarch64-unknown-linux-musl" ;; \
      *)             ARCH="x86_64-unknown-linux-musl" ;; \
    esac && \
    curl -sSfL "https://github.com/cargo-bins/cargo-binstall/releases/download/v${BINSTALL_VERSION}/cargo-binstall-${ARCH}.tgz" \
    | tar -xz -C /usr/local/cargo/bin cargo-binstall

RUN cargo binstall --no-confirm \
    cargo-nextest@0.9.140 \
    cargo-audit@0.22.2

FROM rust:1.94.1-bookworm

RUN rustup component add clippy rustfmt

COPY --from=builder /usr/local/cargo/bin/cargo-nextest /usr/local/cargo/bin/
COPY --from=builder /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/
