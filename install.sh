#!/bin/sh
set -eu

REPO_ENCODED="ThomasTartrau%2Fslopguard"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

main() {
    detect_platform
    fetch_latest_version
    download_and_install
    print_success
}

detect_platform() {
    OS=$(uname -s)
    ARCH=$(uname -m)

    case "$OS" in
    Linux)
        case "$ARCH" in
        x86_64 | amd64) TARGET="x86_64-unknown-linux-musl" ;;
        *) error "unsupported architecture for Linux: $ARCH (only x86_64 is supported)" ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
        x86_64 | amd64) TARGET="x86_64-apple-darwin" ;;
        arm64 | aarch64) TARGET="aarch64-apple-darwin" ;;
        *) error "unsupported architecture for macOS: $ARCH" ;;
        esac
        ;;
    *) error "unsupported OS: $OS (only Linux and macOS are supported)" ;;
    esac
}

fetch_latest_version() {
    if [ -n "${VERSION:-}" ]; then
        return
    fi

    printf "Fetching latest version... "
    RELEASES=$(curl -fsSL "https://gitlab.com/api/v4/projects/${REPO_ENCODED}/releases")
    LATEST_TAG=$(printf '%s' "$RELEASES" | grep -o '"tag_name":"slopguard-cli-v[^"]*"' | head -1 | cut -d'"' -f4)

    if [ -z "$LATEST_TAG" ]; then
        echo ""
        error "could not determine latest version"
    fi

    VERSION="${LATEST_TAG#slopguard-cli-v}"
    echo "v${VERSION}"
}

download_and_install() {
    ARCHIVE="slopguard-${VERSION}-${TARGET}.tar.gz"
    URL="https://gitlab.com/api/v4/projects/${REPO_ENCODED}/packages/generic/slopguard/${VERSION}/${ARCHIVE}"

    echo "Downloading slopguard v${VERSION} for ${TARGET}..."

    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT

    if ! curl -fsSL "$URL" -o "${TMPDIR}/${ARCHIVE}"; then
        error "download failed. Check that v${VERSION} has a binary for ${TARGET}"
    fi

    tar -xzf "${TMPDIR}/${ARCHIVE}" -C "$TMPDIR"
    mkdir -p "$INSTALL_DIR"
    install -m 755 "${TMPDIR}/slopguard-${VERSION}-${TARGET}/slopguard" "${INSTALL_DIR}/slopguard"
}

print_success() {
    echo ""
    echo "slopguard v${VERSION} installed to ${INSTALL_DIR}/slopguard"

    case ":${PATH}:" in
    *":${INSTALL_DIR}:"*)
        ;;
    *)
        echo ""
        echo "Add to your PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        ;;
    esac

    echo ""
    "${INSTALL_DIR}/slopguard" --version
}

error() {
    echo "Error: $1" >&2
    exit 1
}

main
