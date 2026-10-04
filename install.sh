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

validate_version() {
    case "$VERSION" in
    '' | *[!0-9.v]*) error "invalid version: refusing characters outside [0-9.v]" ;;
    esac

    if ! printf '%s' "$VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+$'; then
        error "invalid version: ${VERSION} (expected MAJOR.MINOR.PATCH)"
    fi

    VERSION="${VERSION#v}"
}

fetch_latest_version() {
    if [ -n "${VERSION:-}" ]; then
        validate_version
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
    validate_version
    echo "v${VERSION}"
}

verify_checksum() {
    if [ ! -s "${WORKDIR}/SHA256SUMS" ]; then
        error "SHA256SUMS is empty"
    fi

    awk -v f="$ARCHIVE" '$2 == f' "${WORKDIR}/SHA256SUMS" > "${WORKDIR}/expected"
    MATCHES=$(wc -l < "${WORKDIR}/expected" | tr -d ' ')
    if [ "$MATCHES" != "1" ]; then
        error "SHA256SUMS must list ${ARCHIVE} exactly once (found ${MATCHES})"
    fi

    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$WORKDIR" && sha256sum -c expected >/dev/null 2>&1) || error "checksum verification failed"
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$WORKDIR" && shasum -a 256 -c expected >/dev/null 2>&1) || error "checksum verification failed"
    else
        error "no sha256 tool found (need sha256sum or shasum)"
    fi
}

check_archive() {
    PREFIX="slopguard-${VERSION}-${TARGET}"

    tar -tzf "$ARCHIVE_PATH" > "${WORKDIR}/entries" 2>/dev/null || error "could not list archive contents"
    tar -tvzf "$ARCHIVE_PATH" > "${WORKDIR}/entries-verbose" 2>/dev/null || error "could not list archive contents"

    if [ "$(wc -l < "${WORKDIR}/entries" | tr -d ' ')" != "$(wc -l < "${WORKDIR}/entries-verbose" | tr -d ' ')" ]; then
        error "unsafe archive: unexpected entry names"
    fi

    # Only regular files and directories are allowed (no symlinks, hardlinks, devices).
    if cut -c1 "${WORKDIR}/entries-verbose" | grep -q '[^-d]'; then
        error "unsafe archive: contains links or special files"
    fi

    while IFS= read -r entry; do
        case "$entry" in
        /* | .. | ../* | */../* | */..)
            error "unsafe archive entry: ${entry}"
            ;;
        "$PREFIX" | "$PREFIX"/*) ;;
        *)
            error "unexpected archive entry: ${entry}"
            ;;
        esac
    done < "${WORKDIR}/entries"
}

download_and_install() {
    ARCHIVE="slopguard-${VERSION}-${TARGET}.tar.gz"
    BASE_URL="https://gitlab.com/api/v4/projects/${REPO_ENCODED}/packages/generic/slopguard/${VERSION}"
    URL="${BASE_URL}/${ARCHIVE}"
    SUMS_URL="${BASE_URL}/SHA256SUMS"

    echo "Downloading slopguard v${VERSION} for ${TARGET}..."

    WORKDIR=$(mktemp -d)
    trap 'rm -rf "$WORKDIR"' EXIT
    ARCHIVE_PATH="${WORKDIR}/${ARCHIVE}"

    if ! curl -fsSL "$URL" -o "$ARCHIVE_PATH"; then
        error "download failed. Check that v${VERSION} has a binary for ${TARGET}"
    fi

    if ! curl -fsSL "$SUMS_URL" -o "${WORKDIR}/SHA256SUMS"; then
        error "could not download SHA256SUMS for v${VERSION}; refusing to install an unverified binary"
    fi

    verify_checksum
    check_archive

    BINARY="${WORKDIR}/slopguard-${VERSION}-${TARGET}/slopguard"
    tar -xzf "$ARCHIVE_PATH" -C "$WORKDIR" "slopguard-${VERSION}-${TARGET}/slopguard" || error "could not extract the binary"

    if [ ! -f "$BINARY" ] || [ -L "$BINARY" ]; then
        error "archive does not contain a regular slopguard binary"
    fi

    mkdir -p "$INSTALL_DIR"
    install -m 755 "$BINARY" "${INSTALL_DIR}/slopguard"
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
