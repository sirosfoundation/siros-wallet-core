#!/bin/sh
# Prints the sha256 manifest of the zkp_req conformance vectors and the vector
# set digest: the sha256 of that manifest (LC_ALL=C sorted, `sha256sum` format,
# paths relative to crates/, README.md files excluded).
#
#   scripts/vectors_digest.sh            # manifest, then "set digest: <hex>"
#   scripts/vectors_digest.sh --digest   # only the hex digest
set -eu
cd "$(dirname "$0")/../crates"
dirs="siros-zkp-req/tests/vectors/request siros-zkp-req-nym-auth/tests/vectors"
for dir in $dirs; do
    [ -d "$dir" ] || { echo "vectors_digest: required vector directory missing: $dir" >&2; exit 1; }
done
files=$(find $dirs -name '*.json' | LC_ALL=C sort)
[ -n "$files" ] || { echo "vectors_digest: no vectors found" >&2; exit 1; }
manifest=$(printf '%s\n' "$files" | xargs sha256sum)
digest=$(printf '%s\n' "$manifest" | sha256sum | cut -d' ' -f1)
if [ "${1:-}" = "--digest" ]; then echo "$digest"; else printf '%s\nset digest: %s\n' "$manifest" "$digest"; fi
