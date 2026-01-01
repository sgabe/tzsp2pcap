#!/bin/sh
set -e

USER=tzsp2pcap
UID=${UID:-1000}
GID=${GID:-1000}

if [ "$(id -g "$USER")" != "$GID" ]; then
    groupmod -o -g "$GID" "$USER"
fi

if [ "$(id -u "$USER")" != "$UID" ]; then
    usermod -o -u "$UID" "$USER"
fi

chown -R "$UID:$GID" /data

exec su-exec "$USER" "$@"