#!/bin/sh
# Idempotent self-signed TLS cert for local/demo use — this stack has no
# real domain to get a CA-signed cert for. Runs on every container start
# but only generates once; the cert lives on the nginxcerts volume so it
# survives restarts.
set -e

CERT_DIR=/etc/nginx/certs
CERT="$CERT_DIR/fullchain.pem"
KEY="$CERT_DIR/privkey.pem"

if [ -f "$CERT" ] && [ -f "$KEY" ]; then
    exit 0
fi

mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
    -keyout "$KEY" -out "$CERT" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,DNS:gateway,DNS:frontend"
