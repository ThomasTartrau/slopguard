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
    cargo-audit@0.22.2 \
    cargo-zigbuild@0.20.8

FROM rust:1.94.1-bookworm

ARG ZIG_VERSION=0.14.1
RUN case "$(uname -m)" in \
      aarch64|arm64) ZIG_ARCH="aarch64" ;; \
      *)             ZIG_ARCH="x86_64" ;; \
    esac && \
    mkdir -p /opt/zig && \
    curl -sSfL "https://ziglang.org/download/${ZIG_VERSION}/zig-linux-${ZIG_ARCH}-${ZIG_VERSION}.tar.xz" \
    | tar -xJ --strip-components=1 -C /opt/zig

ENV PATH="/opt/zig:${PATH}"

RUN rustup component add clippy rustfmt && \
    rustup target add x86_64-unknown-linux-musl aarch64-apple-darwin x86_64-apple-darwin

COPY --from=builder /usr/local/cargo/bin/cargo-nextest /usr/local/cargo/bin/
COPY --from=builder /usr/local/cargo/bin/cargo-audit /usr/local/cargo/bin/
COPY --from=builder /usr/local/cargo/bin/cargo-zigbuild /usr/local/cargo/bin/
