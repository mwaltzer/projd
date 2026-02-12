#!/usr/bin/env sh
set -eu

echo "agent indexer ready"
trap 'echo "agent indexer stopping"; exit 0' TERM INT

while true; do
  echo "agent indexer tick"
  sleep 10
done
