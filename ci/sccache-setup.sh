# Sourced by the before_script of every job that runs cargo:
#   . ci/sccache-setup.sh
# Keeps RUSTC_WRAPPER=sccache only when the shared cache is usable, otherwise
# the job compiles without cache instead of failing: the image may predate
# sccache, the SCCACHE_AWS_* credentials may be unset, or MinIO may be out of
# reach (a runner outside the homelab cluster).

sccache_off() {
  echo "sccache disabled: $1, compiling without cache"
  unset RUSTC_WRAPPER
}

if ! command -v sccache >/dev/null 2>&1; then
  sccache_off "binary not found in the image"
elif [ -z "${SCCACHE_AWS_ACCESS_KEY_ID:-}" ] || [ -z "${SCCACHE_AWS_SECRET_ACCESS_KEY:-}" ]; then
  sccache_off "SCCACHE_AWS_* credentials not set"
else
  export AWS_ACCESS_KEY_ID="$SCCACHE_AWS_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$SCCACHE_AWS_SECRET_ACCESS_KEY"
  # The server checks the storage on startup and refuses to start without it.
  if ! sccache --start-server; then
    sccache_off "server could not start (storage unreachable?)"
  fi
fi
