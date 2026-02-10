#!/bin/bash
set -e

# Import matchlock MITM CA into Chromium's NSS database so Playwright trusts it
MATCHLOCK_CA="/etc/ssl/certs/matchlock-ca.crt"
if [ -f "$MATCHLOCK_CA" ]; then
    NSSDB="$HOME/.pki/nssdb"
    mkdir -p "$NSSDB"
    if [ ! -f "$NSSDB/cert9.db" ]; then
        certutil -d sql:"$NSSDB" -N --empty-password
    fi
    certutil -d sql:"$NSSDB" -A -t "C,," -n "matchlock-ca" -i "$MATCHLOCK_CA"
fi

CLAUDE_ARGS="--dangerously-skip-permissions --mcp-config /home/agent/browser-use/.mcp.json"

if [ $# -eq 0 ]; then
    exec claude $CLAUDE_ARGS
else
    exec claude $CLAUDE_ARGS -p "$*"
fi
