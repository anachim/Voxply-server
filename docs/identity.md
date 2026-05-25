# Identity & Auth

Voxply has no accounts and no passwords. Identity is an Ed25519 keypair
held by the device. Everything else (membership, permissions, history)
hangs off the public key.

## Where identity lives

- **Generation**: `voxply-identity/src/lib.rs` (Ed25519 + BIP39 phrase)
- **Recovery phrase**: `voxply-identity/src/recovery.rs` (24 words)
- **Wire types (signed envelopes)**: `voxply-identity/src/wire.rs` — the
  exact byte layouts used for `SubkeyCert`, `HomeHubList`,
  `RevocationEntry`, `SignedPrefsBlob`, pairing messages, and
  `PublicHubProfile`. Each carries a versioned domain-separation prefix
  (e.g. `voxply/subkey-cert/v1\0`) that any reimplementation must match
  byte-for-byte.
- **Storage on the desktop client**: a JSON file in Tauri's app-data dir,
  written by the Rust side of the desktop client.

The recovery phrase **is** the secret — entering it on a device replaces
that device's identity (in legacy single-key mode) or seeds the master
identity (in master+subkey mode; see [multi-device.md](multi-device.md)).

## How auth works against a hub

Challenge-response, signature-based:

1. Client requests a challenge from the hub.
2. Hub returns a random nonce.
3. Client signs the nonce with its Ed25519 private key.
4. Client posts the signature + public key.
5. Hub verifies and issues a session token.

Code path: `voxply-hub/src/auth/handlers.rs` and
`voxply-hub/src/auth/middleware.rs`. Wire shapes (the JSON the client
sends and receives) are in `voxply-hub/src/auth/models.rs`.

**Protocol reference**: `openapi.yaml` at the repo root is the
machine-readable contract for every REST endpoint — auth flow, request
and response schemas, PoW algorithm, security-level proofs, pairing
handshake, federation calls, bot API. Third-party clients should treat
that file as the single source of truth and read the Rust code only
when the spec is ambiguous.

## Authorization (after auth)

A user's pubkey is matched to their hub-local membership row, which
carries their roles. Roles bundle permissions; see
`voxply-hub/src/permissions.rs` for the permission set and
`voxply-hub/src/routes/roles.rs` for role CRUD.

Common permissions: `manage_hub`, `manage_channels`, `manage_roles`,
`manage_users`, `send_messages`, `attach_files`, etc.

## Hub-to-hub auth (federation)

Same primitive, different actor: each hub also has its own Ed25519
keypair. When Hub A talks to Hub B, A signs requests as itself; B
verifies. See `voxply-hub/src/federation/client.rs` and
`voxply-hub/src/federation/handlers.rs`.

## Recovery flow

1. User generates an identity → 24-word phrase shown once.
2. User pastes phrase on a new device (or the same device after wipe).
3. The phrase deterministically yields the Ed25519 keypair. Same phrase
   ⇒ same pubkey ⇒ same identity to every hub.

This is "one device per account" — pasting a phrase doesn't sync; it
*replaces* the device's identity. Both devices having the same phrase
means both have the same key, with no coordination between them.

## Master + per-device subkey

The master+subkey model is wired in. `voxply-identity/src/master.rs`
derives the master keypair from the recovery phrase via HKDF;
`voxply-identity/src/subkey.rs` produces per-device subkeys whose certs
are master-signed (`SubkeyCert` in `wire.rs`). On the hub, the canonical
user row is the master pubkey — see
`voxply-hub/src/auth/handlers.rs::resolve_canonical_identity` for how a
device subkey + cert resolves to the existing canonical row, including
the legacy-upgrade path that preserves the pre-existing pubkey when
migrating an older single-key identity.

Legacy single-key auth still works: clients that never present a cert
authenticate exactly as before, and `master_pubkey` stays NULL on their
user row. See [multi-device.md](multi-device.md) for the pairing
protocol and [decisions.md](decisions.md) for the rationale.

## Anti-spam (PoW)

Proof-of-work knobs live in `voxply-identity/src/pow.rs`. A hub admin
sets `min_security_level` (number of leading zero bits required) in
hub settings; clients prove they meet it by submitting `security_nonce`
+ `security_level` on `/auth/verify`, or after the fact via
`/lobby/submit-pow`. Hashing scheme: `SHA-256(public_key_hex_ascii ||
nonce_le_u64)` — that exact concatenation is what
`hash_level` in `pow.rs` computes, and what `openapi.yaml` documents
for third-party implementers.
