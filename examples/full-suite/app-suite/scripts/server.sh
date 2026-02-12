#!/usr/bin/env sh
set -eu

echo "APP_READY port=${APP_PORT:-${PORT}}"
trap 'echo "app-suite server stopping"; exit 0' TERM INT

while true; do
  echo "app-suite server heartbeat"
  sleep 6
done
