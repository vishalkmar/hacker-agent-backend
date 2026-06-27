# CypherMind sandbox image

The agent runs its commands inside this container (Phase 4) instead of on your host, so it
has real Kali tools and can't touch your machine.

## Prereqs
- **Docker Desktop** installed and **running** (the daemon must be up).
  This machine already has the Docker CLI; just start Docker Desktop.

## Build the image (one time)
```bash
cd backend/docker
docker build -t cyphermind/kali:latest -f Dockerfile.kali .
# full arsenal (heavy): docker build -t cyphermind/kali-everything:latest -f Dockerfile.kali-everything .
```
First build is large (Kali + tools, a few GB) and can take a while.

> This folder lives **inside `backend/`** so the backend is self-contained: when you deploy the
> backend, the sandbox Dockerfiles + the scripts the server reads at runtime
> (`extract-tool-docs.sh`, `audit-tools.sh`) ship with it.

## How the backend uses it
- `backend/.env` → `EXEC_BACKEND=auto` uses Docker when the daemon is reachable, else falls
  back to host bash automatically.
- Each chat session gets its own container `cyphermind_<sessionId>` with a `/workspace`
  volume. Manage via `GET /api/sandbox/status` and `POST /api/sandbox/reset`.

## Add more tools
Edit `Dockerfile.kali` and rebuild, or for the full Kali set add:
```dockerfile
RUN apt-get update && apt-get install -y kali-linux-large && rm -rf /var/lib/apt/lists/*
```
(Very large.) Or let the agent `apt-get install <tool>` inside a running session.
