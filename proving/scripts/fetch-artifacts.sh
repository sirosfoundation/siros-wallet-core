#!/usr/bin/env bash
# Downloads the circuit artifacts the system rulebooks pin (Section 8) from their reference copies
# in readdit-demo at the commit of Section 10, and checks them against the pins.
#
#   proving/scripts/fetch-artifacts.sh    # writes proving/artifacts/{longfellow,vega}/
set -eu
cd "$(dirname "$0")/.."
base=https://raw.githubusercontent.com/AltmannPeter/readdit-demo/1cf3f2610318e896b0a1cde4b30d6b15d94ccfd0/native
fetch() {
    local system="$1"
    local name="$2"
    local path="$3"
    local pin="$4"
    mkdir -p "artifacts/$system"
    curl --proto '=https' -fsSL -o "artifacts/$system/$name" "$base/$path"
    echo "$pin  artifacts/$system/$name" | sha256sum -c -
}
fetch longfellow circuits.zst longfellow/circuits/mdoc/circuits.zst \
    6c4b96ed431ee547a3a2e5b62621943a9a0a44646267653bf2db0fcc269b5c3b
fetch vega shapes.zst vega/circuits/mdoc/shapes.zst \
    b457ba5382eb7604ef035e790f2cb24f0cd5fdcd065f383ff1c2c49fab1bb4df
