# Nyx project status

Status date: 2026-08-27

Nyx is an architecture/MVP implementation. It is not security-audited and is
not suitable for sensitive or production communication.

## Implemented

### Mailbox server

- Arti 0.45 bootstraps Tor and publishes a persistent v3 Onion Service.
- The service accepts streams directly on virtual Onion port 443. There is no
  local TCP proxy and no Clearnet fallback.
- A length-prefixed Postcard protocol supports depositing, fetching, and
  acknowledging opaque envelopes.
- SQLite persists only the mailbox token, ciphertext, protocol version,
  timestamps, expiry, and an opaque deterministic receipt. The server does not
  receive or parse message plaintext, contacts, conversation IDs, or sender IDs.
- Envelopes expire after seven days. Expired rows are removed during mailbox
  operations.
- Bounds currently enforced: 1 MiB frame size, 128 fetched/acknowledged items
  per request, 1,024 retained messages per mailbox token, a bounded response,
  and a 30-second stream timeout.
- A receipt is a BLAKE3 digest of the serialized envelope. Deletion requires
  both the mailbox token and receipt. Duplicate deposits are idempotent.
- Logs intentionally omit mailbox tokens, receipts, and ciphertext.

### Other components

- The Dioxus desktop scaffold builds and runs.
- `nyx-tor` now bootstraps an Arti client, accepts only syntactically valid v3
  `.onion` endpoints, and implements bounded deposit/fetch/ack requests with a
  60-second timeout. It exposes no Clearnet connection method.
- `nyx-mailbox-smoke` is an opt-in live-Tor test tool. It uses a random mailbox
  token and random synthetic ciphertext to verify deposit, byte-identical fetch,
  acknowledgement, and deletion without transmitting user content.
- Domain types for contacts and chat messages exist.
- Envelope and encrypted-message serialization exists.
- `nyx-crypto` generates an Ed25519 basic device credential and an RFC 9420
  KeyPackage using OpenMLS with the X25519/AES-128-GCM/SHA-256 ciphersuite. The
  provider is currently memory-backed and explicitly not production-persistent.
- The SQLite client-store boundary remains a scaffold.
- The workspace currently has nine crypto/transport/mailbox/protocol unit tests
  covering MLS device material validation, request serialization,
  oversized-frame rejection, receipt binding, mailbox lifecycle, cross-mailbox
  ACK isolation, Onion endpoint validation, and invalid input rejection.

## Not implemented

- The desktop UI is not connected to the implemented `nyx-tor` transport.
- OpenMLS group creation/joining, encryption, decryption, commits, and encrypted
  key persistence are not implemented. Device credentials and KeyPackages are
  currently volatile foundations only.
- Device identity generation, contact invitations, out-of-band verification,
  and multi-device behavior are not implemented.
- The local client store is not encrypted and contains only a generic `kv`
  scaffold.
- Attachment transfer, padding buckets, batching, cover traffic, token
  rotation, retries, encrypted ACK payloads, and optional direct peer Onion
  Services are not implemented.
- Onion client authorization, operator authentication, quotas across mailbox
  tokens, global disk quotas, and production-grade abuse controls are not
  implemented.
- There is no migration/version-management system for the mailbox database.
- The live-Tor smoke test is manual and has not been automated in CI. There are
  no parser fuzz tests, load tests, backup/restore procedures, deployment
  manifests, or monitoring.

## Security limitations

- Mailbox SQLite pages are not encrypted at rest. Stored message bodies are
  already expected to be MLS ciphertext, but mailbox tokens and timing/size
  metadata remain visible to anyone who obtains the database.
- The deterministic receipt exposes equality of identical serialized
  envelopes. This does not reveal plaintext, but it is metadata.
- SQLite work currently runs synchronously behind one process mutex. The
  request timeout and limits reduce exposure but do not constitute complete DoS
  protection.
- Mailbox access timing, token reuse, ciphertext sizes, and retention metadata
  remain observable to a compromised server.
- Arti's Onion Service identity is stored through Arti's configured keystore.
  Operators must protect and back up that state using appropriate filesystem
  permissions and encryption.
- No security audit, dependency audit, parser fuzzing, or log-redaction audit
  has been completed.

## Verified in this revision

```bash
cargo fmt --all -- --check
cargo test --workspace
```

Both commands pass. A successful compile and unit-test run does not verify
publication or reachability on the public Tor network.

## Next milestone

The next useful milestone is OpenMLS identity, group, and persistence
integration with deterministic local tests. That must precede wiring real
message content into the transport or desktop UI. The manual live-Tor smoke test
should later become an isolated, opt-in CI job.
