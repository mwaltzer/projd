#!/usr/bin/env sh
set -eu

echo "DEP_READY port=${PORT}"
trap 'echo "dep-service stopping"; exit 0' TERM INT

while true; do
  echo "dep-service heartbeat"
  sleep 8
done
