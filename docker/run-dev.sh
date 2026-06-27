#!/usr/bin/env bash
# One command to run the backend in "full tools" mode.
# - Verifies the Docker daemon is up
# - Builds the Kali sandbox image if it's missing
# - Starts the backend (which then `docker exec`s into Kali for every tool)
#
# Usage:
#   bash backend/docker/run-dev.sh            # lean image (~30 core tools, fast)
#   IMAGE=everything bash backend/docker/run-dev.sh   # full kali-linux-everything (heavy)
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
BACKEND="$(cd "$HERE/.." && pwd)"

if [ "${IMAGE:-lean}" = "everything" ]; then
  TAG="cyphermind/kali-everything:latest"; FILE="Dockerfile.kali-everything"
else
  TAG="cyphermind/kali:latest"; FILE="Dockerfile.kali"
fi

echo ">> Checking Docker daemon…"
if ! docker info >/dev/null 2>&1; then
  echo "!! Docker daemon is not running. Start Docker Desktop and re-run."; exit 1
fi

if docker image inspect "$TAG" >/dev/null 2>&1; then
  echo ">> Image $TAG already present."
else
  echo ">> Building $TAG (first build is large; please wait)…"
  ( cd "$HERE" && docker build -t "$TAG" -f "$FILE" . )
fi

echo ">> Starting backend with EXEC_BACKEND=docker, EXEC_IMAGE=$TAG"
cd "$BACKEND"
EXEC_BACKEND=docker EXEC_IMAGE="$TAG" npm run dev
