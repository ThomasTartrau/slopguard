#!/bin/sh
# Tests for install.sh. Serves fixture archives through a curl shim, runs the
# installer against an isolated INSTALL_DIR and asserts what got installed.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

VERSION_OK="1.2.3"
TARGET="x86_64-unknown-linux-musl"
PREFIX="slopguard-${VERSION_OK}-${TARGET}"
ARCHIVE="${PREFIX}.tar.gz"
FAILURES=0

# PATH shims: fixed platform and a curl serving files from $SERVE_DIR.
mkdir -p "${WORK}/shim"
cat > "${WORK}/shim/uname" <<'SHIM'
#!/bin/sh
case "$1" in
-s) echo Linux ;;
-m) echo x86_64 ;;
esac
SHIM
cat > "${WORK}/shim/curl" <<'SHIM'
#!/bin/sh
url=""
out=""
while [ $# -gt 0 ]; do
    case "$1" in
    -o) out="$2"; shift ;;
    -*) ;;
    *) url="$1" ;;
    esac
    shift
done
src="${SERVE_DIR}/$(basename "$url")"
[ -f "$src" ] || exit 22
cp "$src" "$out"
SHIM
chmod +x "${WORK}/shim/uname" "${WORK}/shim/curl"

sum_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$1" && sha256sum "$ARCHIVE" > SHA256SUMS)
    else
        (cd "$1" && shasum -a 256 "$ARCHIVE" > SHA256SUMS)
    fi
}

# new_case NAME: prepares a case directory with a good staging tree.
new_case() {
    CASE="${WORK}/$1"
    mkdir -p "${CASE}/serve" "${CASE}/stage/${PREFIX}" "${CASE}/install"
    printf '#!/bin/sh\necho "slopguard %s"\n' "$VERSION_OK" > "${CASE}/stage/${PREFIX}/slopguard"
    chmod +x "${CASE}/stage/${PREFIX}/slopguard"
}

pack_good() {
    tar -czf "${CASE}/serve/${ARCHIVE}" -C "${CASE}/stage" "$PREFIX"
}

# run_installer VERSION: runs install.sh, sets RC and OUT.
run_installer() {
    RC=0
    OUT=$(PATH="${WORK}/shim:${PATH}" SERVE_DIR="${CASE}/serve" INSTALL_DIR="${CASE}/install" VERSION="$1" sh "${ROOT}/install.sh" 2>&1) || RC=$?
}

check() {
    if [ "$2" = "ok" ]; then
        echo "ok   - $1"
    else
        echo "FAIL - $1"
        echo "$OUT" | sed 's/^/       /'
        FAILURES=$((FAILURES + 1))
    fi
}

assert_installed() {
    if [ "$RC" -eq 0 ] && [ -x "${CASE}/install/slopguard" ]; then check "$1" ok; else check "$1" fail; fi
}

assert_aborted() {
    if [ "$RC" -ne 0 ] && [ ! -e "${CASE}/install/slopguard" ]; then check "$1" ok; else check "$1" fail; fi
}

# Good archive installs.
new_case good
pack_good
sum_file "${CASE}/serve"
run_installer "$VERSION_OK"
assert_installed "good archive installs"

# A leading v is accepted and normalised.
new_case vprefix
pack_good
sum_file "${CASE}/serve"
run_installer "v${VERSION_OK}"
assert_installed "version with v prefix installs"

# Tampered archive: checksum no longer matches.
new_case tampered
pack_good
sum_file "${CASE}/serve"
printf 'tamper' >> "${CASE}/serve/${ARCHIVE}"
run_installer "$VERSION_OK"
assert_aborted "tampered archive installs nothing"

# Missing SHA256SUMS.
new_case nosums
pack_good
run_installer "$VERSION_OK"
assert_aborted "missing SHA256SUMS installs nothing"

# SHA256SUMS lacking the archive line.
new_case nolines
pack_good
echo "0000000000000000000000000000000000000000000000000000000000000000  other.tar.gz" > "${CASE}/serve/SHA256SUMS"
run_installer "$VERSION_OK"
assert_aborted "SHA256SUMS without the archive installs nothing"

# Duplicated SHA256SUMS lines.
new_case dupes
pack_good
sum_file "${CASE}/serve"
cat "${CASE}/serve/SHA256SUMS" "${CASE}/serve/SHA256SUMS" > "${CASE}/serve/SUMS2"
mv "${CASE}/serve/SUMS2" "${CASE}/serve/SHA256SUMS"
run_installer "$VERSION_OK"
assert_aborted "duplicated SHA256SUMS lines install nothing"

# Invalid versions.
for bad in "1.0" "1.0.0;x" "1.0.0/../x" "latest" "1.0.0-rc1"; do
    new_case badversion
    pack_good
    sum_file "${CASE}/serve"
    run_installer "$bad"
    assert_aborted "invalid version '${bad}' aborts"
done

# Malicious archives, each with a matching checksum.
new_case dotdot
mkdir -p "${CASE}/stage/inner"
echo evil > "${CASE}/stage/evil"
tar -czPf "${CASE}/serve/${ARCHIVE}" -C "${CASE}/stage/inner" ../evil
sum_file "${CASE}/serve"
run_installer "$VERSION_OK"
assert_aborted "archive with .. entry aborts"

new_case absolute
echo evil > "${CASE}/stage/abs-evil"
tar -czPf "${CASE}/serve/${ARCHIVE}" "${CASE}/stage/abs-evil"
sum_file "${CASE}/serve"
run_installer "$VERSION_OK"
assert_aborted "archive with absolute path aborts"

new_case symlink
rm "${CASE}/stage/${PREFIX}/slopguard"
ln -s /bin/sh "${CASE}/stage/${PREFIX}/slopguard"
pack_good
sum_file "${CASE}/serve"
run_installer "$VERSION_OK"
assert_aborted "archive with symlink entry aborts"

new_case extra
echo extra > "${CASE}/stage/extra-file"
tar -czf "${CASE}/serve/${ARCHIVE}" -C "${CASE}/stage" "$PREFIX" extra-file
sum_file "${CASE}/serve"
run_installer "$VERSION_OK"
assert_aborted "archive with entry outside the release directory aborts"

if [ "$FAILURES" -ne 0 ]; then
    echo "${FAILURES} test(s) failed" >&2
    exit 1
fi
echo "all install tests passed"
