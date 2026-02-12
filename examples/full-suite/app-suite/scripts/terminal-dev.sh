#!/usr/bin/env sh
set -eu

echo "terminal dev shell started"
trap 'echo "terminal dev shell stopping"; exit 0' TERM INT

while true; do
  echo "terminal dev shell alive"
  sleep 12
done
