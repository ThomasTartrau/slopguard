#!/bin/sh
# Uploads a release asset to the generic package registry and links it to the
# release of $CI_COMMIT_TAG. Safe to rerun on a published tag: the registry
# accepts duplicates and serves the latest file, and an existing link is kept.
#
# Usage: ci/publish-asset.sh <file> <link_type>
#
# Every call authenticates with the job token. Release tags are not protected,
# so protected variables such as GITLAB_TOKEN are empty in tag pipelines.
set -eu

FILE="$1"
LINK_TYPE="$2"
NAME=$(basename "$FILE")
VERSION="${CI_COMMIT_TAG#slopguard-cli-v}"
PROJ_API="${CI_API_V4_URL}/projects/${CI_PROJECT_ID}"
PKG_URL="${PROJ_API}/packages/generic/slopguard/${VERSION}/${NAME}"
LINKS_URL="${PROJ_API}/releases/${CI_COMMIT_TAG}/assets/links"

api() {
  curl --silent --show-error --fail-with-body --header "JOB-TOKEN: ${CI_JOB_TOKEN}" "$@"
}

api --upload-file "$FILE" "$PKG_URL"
echo

LINKS=$(api "${LINKS_URL}?per_page=100") || {
  echo "$LINKS" >&2
  exit 1
}
if printf '%s' "$LINKS" | grep -qF "\"name\":\"${NAME}\""; then
  echo "release link ${NAME} already exists, skipping"
  exit 0
fi

api --request POST "$LINKS_URL" \
  --data-urlencode "name=${NAME}" \
  --data-urlencode "url=${PKG_URL}" \
  --data-urlencode "link_type=${LINK_TYPE}"
echo
