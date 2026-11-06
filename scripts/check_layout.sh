#!/bin/sh
# AGENTS.md's layout rules, each count 0:
# - test code under the plan's crates' and xtask's `src/`: a test attribute or a `cfg` naming `test`;
# - message sources (`.mf2`) in the crates outside siros-testkit's test app and the `tests/`
#   directories.
# Prints each hit; exits 1 when a count is not 0.
set -eu
cd "$(dirname "$0")/.."
tests=$(find crates/siros-*/src xtask/src -name '*.rs' -exec grep -nHE \
    '#!?\[[[:space:]]*(([a-z_]+::)?(test|wasm_bindgen_test)[[:space:]]*[]()]|cfg[[:space:]]*\(([^]]*[(,[:space:]])?test[[:space:]]*[,)])' {} + || true)
sources=$(find crates -name '*.mf2' -not -path 'crates/siros-testkit/*' -not -path '*/tests/*' | LC_ALL=C sort)
count() { [ -z "$1" ] && echo 0 || printf '%s\n' "$1" | wc -l; }
echo "test code under src/: $(count "$tests")"
[ -z "$tests" ] || printf '%s\n' "$tests" | sed 's/^/  /'
echo "message sources outside the test app and tests/: $(count "$sources")"
[ -z "$sources" ] || printf '%s\n' "$sources" | sed 's/^/  /'
[ -z "$tests" ] && [ -z "$sources" ]
