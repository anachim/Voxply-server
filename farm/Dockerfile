# Build the farm binary.
# Run from the workspace root:
#
#   docker build -f farm/Dockerfile -t ghcr.io/voxply/farm:latest .
#
# Or use docker-compose.farm.yml from the workspace root.

FROM rust:1-slim AS builder

RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . .
RUN cargo build --release -p voxply-farm

# ---------- runtime ----------
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/*

# The farm writes farm.db and farm_identity.json into the working directory.
WORKDIR /data
VOLUME ["/data"]

COPY --from=builder /build/target/release/voxply-farm /usr/local/bin/voxply-farm

# Farm HTTP API
EXPOSE 4000

# All env vars the farm reads. Override in docker-compose.yml or with -e flags.
ENV VOXPLY_FARM_HTTP_PORT=4000
# The externally reachable URL of this farm — used in session tokens.
# Must be set correctly in production.
# ENV VOXPLY_FARM_URL=https://farm.example.com
# Path to the hub binary for auto-spawning hubs (Phase 3).
# ENV VOXPLY_HUB_BIN=/usr/local/bin/voxply-hub
# ENV VOXPLY_LOG_FORMAT=json
# ENV VOXPLY_SENTRY_DSN=

ENTRYPOINT ["/usr/local/bin/voxply-farm"]
