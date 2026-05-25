# Voxply-server

Hub server for the [Voxply](https://github.com/YOUR_ORG/Voxply) platform.
Handles authentication, channels, messaging, federation, voice relay,
alliances, bots, security lobby, and all hub-side logic.

Part of the Voxply project — see the
[docs repo](https://github.com/YOUR_ORG/Voxply) for architecture,
API spec, and roadmap.

## Technologies

- **Rust** — memory-safe, async, zero-cost abstractions
- **Axum 0.8** — HTTP + WebSocket server framework
- **SQLite** via sqlx — embedded database, no separate process
- **tokio** — async runtime
- **Ed25519** (voxply-identity) — keypair-based identity, no accounts
- **SHA-256 PoW** — proof-of-work security levels
- **UDP** — raw voice packet relay (codec handled client-side)
- **reqwest** — outbound HTTP for federation

## Repository structure

```
voxply-hub/          Main hub server binary + library
  src/
    auth/            Challenge-response auth, session tokens
    routes/          All HTTP handlers (channels, messages, DMs, bots, …)
    federation/      Hub-to-hub federation client + handlers
    db/              SQLite migrations
voxply-seed/         Seed / discovery scaffold
voxply-identity/     Ed25519 keypairs, PoW, BIP39 recovery, wire types
openapi.yaml         Full API specification (OpenAPI 3.0)
docs/                Architecture docs, design decisions, threat model
```

## Quick start

```bash
cargo run -p voxply-hub
# HTTP on 0.0.0.0:3000  |  Voice UDP on 0.0.0.0:3001
# VOXPLY_HTTP_PORT / VOXPLY_VOICE_UDP_PORT to override
# VOXPLY_TLS_CERT + VOXPLY_TLS_KEY for HTTPS
```

For production deployment (systemd, TLS, backups, upgrades) see
[`docs/hosting.md`](docs/hosting.md).

## Building & testing

```bash
cargo check --workspace          # fast type check
cargo test --workspace           # run all integration tests
cargo build --release -p voxply-hub   # release binary
```

Or using Docker:

```bash
docker compose up --build        # see voxply-hub/docker-compose.yml
```

## API

The complete API reference is in [`openapi.yaml`](openapi.yaml) —
every endpoint, request/response shape, auth flow, and PoW algorithm
documented in OpenAPI 3.0. Implement a client in any language against
this spec.

## Built with AI assistance

This project was built with substantial help from
[Claude](https://claude.ai) (Anthropic's AI assistant). The product
owner directs architecture, features, and tradeoffs; Claude drafts
most of the code, tests, and documentation, which is then reviewed,
adjusted, and accepted.

Calling this out for transparency — it's not a fully hand-written
codebase, and pretending otherwise wouldn't be honest.

## License

[GNU Affero General Public License v3.0](LICENSE). Network use of a
modified version requires offering the corresponding source to users —
important for a federated platform.
