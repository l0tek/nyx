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

See [`docs/project-status.md`](docs/project-status.md) for implemented features,
known limitations, and the remaining security work.

The client transport and cryptographic crates intentionally contain explicit
TODO boundaries. The server-side Arti Onion Service, opaque mailbox storage, and
headless `nyx-tor` mailbox client are implemented, but the desktop UI is not
connected to them. Do not replace the crypto boundary with ad-hoc cryptography.
Integrate and test OpenMLS before enabling real user messaging.

## Security rule

A compromised delivery server must reveal only opaque mailbox tokens, ciphertext sizes/timing and retention metadata - never plaintext, contact lists, group membership or long-lived user identifiers.
