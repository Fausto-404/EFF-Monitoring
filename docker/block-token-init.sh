#!/bin/sh
set -eu

TOKEN_FILE=${BLOCK_RUNNER_TOKEN_FILE:-/run/eff-block-token/token}
if [ ! -s "$TOKEN_FILE" ]; then
    if [ -n "${BLOCK_RUNNER_TOKEN:-}" ] && [ "${#BLOCK_RUNNER_TOKEN}" -lt 32 ]; then
        echo "BLOCK_RUNNER_TOKEN must contain at least 32 characters" >&2
        exit 1
    fi
    umask 077
    candidate=$(mktemp "${TOKEN_FILE}.XXXXXX")
    if [ -n "${BLOCK_RUNNER_TOKEN:-}" ]; then
        printf '%s\n' "$BLOCK_RUNNER_TOKEN" > "$candidate"
    else
        python -c 'import secrets; print(secrets.token_hex(32))' > "$candidate"
    fi
    mv "$candidate" "$TOKEN_FILE"
fi

token=$(tr -d '\r\n' < "$TOKEN_FILE")
if [ "${#token}" -lt 32 ]; then
    echo "Stored block runner token must contain at least 32 characters" >&2
    exit 1
fi
chown 65534:65534 "$TOKEN_FILE"
chmod 600 "$TOKEN_FILE"
echo "Block runner token is ready."
