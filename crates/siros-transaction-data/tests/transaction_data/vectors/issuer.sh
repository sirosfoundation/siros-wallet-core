#!/bin/sh
# Writes issuer.der: a self-signed P-256 certificate, the issuer chain of the test mdocs.
set -eu
key=$(mktemp)
trap 'rm -f "$key"' EXIT
openssl ecparam -name prime256v1 -genkey -noout -out "$key"
openssl req -x509 -new -key "$key" -subj "/CN=Test issuer/O=Test only" -days 3650 \
  -set_serial 1 -outform DER -out "$(dirname "$0")/issuer.der"
