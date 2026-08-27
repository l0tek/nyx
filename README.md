# Nyx

Security-oriented chat architecture using Rust, Dioxus, Tor Onion Services and MLS.

> Status: architecture / MVP scaffold. This repository is **not security-audited** and must not be treated as production-secure software.

## Core design

- Tor-only transport; no Clearnet fallback.
- End-to-end encryption independent of Tor.
- MLS (RFC 9420) via OpenMLS as the intended session/group security layer.
- Minimal-metadata Onion mailbox for asynchronous delivery.
- Optional direct Onion peer transport when both peers are online.
- Local encrypted storage and explicit device identities.
- No telephone number, e-mail account or global username required.

## Workspace

```text
nyx/
├── apps/
│   ├── desktop/            Dioxus desktop client
│   └── mailbox-server/     minimal Onion delivery service
├── crates/
│   ├── nyx-core/     domain model and application logic
│   ├── nyx-crypto/   MLS/E2EE boundary
│   ├── nyx-protocol/ wire envelopes and framing
│   ├── nyx-store/    local persistence boundary
│   ├── nyx-tor/      Arti/Tor boundary
│   └── nyx-ui/       Dioxus components
├── docs/
│   ├── architecture.md
│   └── Nyx_Sicherheitskonzept.pdf
├── SECURITY.md
└── THREAT_MODEL.md
```

## First build target

```bash
cargo build --workspace
```

For the desktop UI with Dioxus CLI 0.7.x, run from `apps/desktop`:

```bash
dx serve --desktop
```

For local development, copy `.env.example` to the workspace-root `.env` and
replace its placeholders. The desktop app and mailbox server load the nearest
`.env` automatically without overriding variables already exported by the
calling process. `.env` is ignored by Git and must not be used as production
secret storage.

Run the mailbox Onion Service from the workspace root:

```bash
cargo run -p nyx-mailbox-server
```

On first start, Arti bootstraps Tor and creates a persistent v3 Onion Service
identity. The server prints its `.onion` address once it is ready and accepts
the Nyx binary mailbox protocol on virtual Onion port `443`. It does not open a
local or Clearnet TCP listener. Opaque envelopes are retained for seven days in
`nyx-mailbox-data/mailbox.sqlite3` by default. Override that directory with
`NYX_MAILBOX_DATA_DIR`.

With the server running and its printed address available, exercise the complete
mailbox flow from another terminal:

```bash
cargo run -p nyx-mailbox-smoke -- <v3-address.onion>
```

The opt-in smoke test generates a fresh random mailbox token and random synthetic
ciphertext, then verifies deposit, fetch, and acknowledgement over Tor. It does
not use real message content and deletes its test envelope on success.

See [`docs/project-status.md`](docs/project-status.md) for implemented features,
known limitations, and the remaining security work.

The client transport and cryptographic crates intentionally contain explicit
TODO boundaries. The server-side Arti Onion Service, opaque mailbox storage, and
headless `nyx-tor` mailbox client are implemented. The desktop app demonstrates a real in-memory
two-member OpenMLS group, Welcome processing, encryption, decryption, and replay
protection. The desktop sidebar can save and unlock the full in-memory OpenMLS
state through the Argon2id/XChaCha20-Poly1305 encrypted store. It writes
`nyx-desktop-state.nyx` by default; use `NYX_DESKTOP_STATE_PATH` to override the
location. When `NYX_RECIPIENT_MAILBOX_TOKEN_HEX` contains a 32-byte token as 64
hexadecimal characters, sent MLS ciphertext is durably queued in
`nyx-delivery.sqlite3`; override it with `NYX_DELIVERY_QUEUE_PATH`. The desktop
flushes this queue automatically when `NYX_MAILBOX_ONION` names a validated v3
Onion endpoint (`NYX_MAILBOX_PORT` defaults to `443`). Configure
`NYX_LOCAL_MAILBOX_TOKEN_HEX` to poll, MLS-decrypt, and acknowledge inbound
messages. After Save or Unlock, inbound ratchet advancement and mailbox receipts
are atomically persisted before acknowledgement; repeats after an ACK failure
are safely recognized. The vault locks after five minutes of inactivity by
default (`NYX_VAULT_LOCK_TIMEOUT_SECS`) and can also be locked explicitly.
Initial saving remains manual. When delivery is configured, outbound ratchet
advancement is atomically journaled in the encrypted vault before an idempotent
handoff to the SQLite delivery queue. Do not replace the crypto boundary with
ad-hoc cryptography or use the demo for sensitive messaging.

## Security rule

A compromised delivery server must reveal only opaque mailbox tokens, ciphertext sizes/timing and retention metadata - never plaintext, contact lists, group membership or long-lived user identifiers.
