#!/usr/bin/env bash
# Build the full Kali-Everything image. Run with Docker Desktop up + internet available.
# Usage: bash backend/docker/build-everything.sh   (works from anywhere; it cd's to its own dir)
set -e
cd "$(dirname "$0")"
IMAGE="${EXEC_IMAGE:-cyphermind/kali-everything:latest}"
echo ">> Building $IMAGE (this is large; expect 10-20 GB and a long build)…"
docker build -t "$IMAGE" -f Dockerfile.kali-everything .
echo ">> Done. Set backend/.env: EXEC_IMAGE=$IMAGE  and  EXEC_BACKEND=docker"
echo ">> Quick check:"
docker run --rm "$IMAGE" bash -lc 'for t in nmap hydra sqlmap nikto gobuster; do printf "%-10s %s\n" "$t" "$(command -v $t || echo MISSING)"; done'
