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

- The Dioxus desktop app builds and exposes an interactive local MLS chat demo.
  Submitted text is encrypted into a real OpenMLS PrivateMessage, processed by
  the invited peer group, and shown only after successful decryption. The UI
  reports ciphertext size and initialization/runtime errors.
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
  active provider is memory-backed; its complete state can be exported into the
  authenticated encrypted snapshot described below.
- `nyx-crypto` creates a two-member group, adds the peer KeyPackage, serializes
  and processes the Welcome, verifies matching epoch authenticators, exchanges
  encrypted application messages, and rejects replayed messages.
- Both OpenMLS provider stores, the group identifier, and signer references can
  be serialized into the encrypted blob store and restored through
  `MlsGroup::load`. A test verifies continued message ratchets after restore and
  rejection of an incorrect password.
- `nyx-store` provides an authenticated encrypted-blob format using Argon2id
  and XChaCha20-Poly1305. Headers are authenticated, derived keys and loaded
  plaintext are zeroized, files are atomically replaced, and Unix temporary
  files use mode `0600`.
- `nyx-store` provides a separate SQLite ciphertext delivery queue. It records
  enqueue time and attempts, validates size/token bounds, and hides delivered
  items only after confirmation. No MLS key material is written to this queue.
- The desktop send path places the exact serialized OpenMLS PrivateMessage into
  that queue when `NYX_RECIPIENT_MAILBOX_TOKEN_HEX` is configured. The queue
  path defaults to `nyx-delivery.sqlite3` and can be overridden with
  `NYX_DELIVERY_QUEUE_PATH`.
- `nyx-tor` can flush queued envelopes in order, record an attempt before each
  request, and mark delivery only after the Onion mailbox confirms deposit.
- The desktop owns an asynchronous worker that validates `NYX_MAILBOX_ONION`,
  bootstraps Tor without a Clearnet fallback, flushes every ten seconds, keeps
  failures queued, and reports bootstrap/delivery/retry state in the sidebar.
- With `NYX_LOCAL_MAILBOX_TOKEN_HEX`, the worker also fetches inbound envelopes,
  processes Bob-to-Alice OpenMLS application messages, displays valid UTF-8
  text, and acknowledges only MLS messages that were processed successfully.
- Inbound MLS processing journals each mailbox receipt inside the same encrypted
  snapshot as the advanced OpenMLS ratchet. The snapshot is atomically replaced
  before acknowledgement; failed saves restore the pre-message ratchet, and
  already-journaled receipts are acknowledged again after an ACK failure or restart.
- Saving or unlocking a vault activates inbound automatic safe-save. The retained
  in-memory password is zeroized when replaced or dropped; inbound processing is
  suspended while the vault is locked.
- The desktop vault locks explicitly or after five minutes of user inactivity by
  default. Locking zeroizes the retained password, drops the live MLS conversation,
  clears displayed messages, and suspends inbound processing. The bounded timeout
  can be configured with `NYX_VAULT_LOCK_TIMEOUT_SECS` (30–86,400 seconds).
- The generic SQLite client-store boundary remains a separate scaffold.
- The desktop sidebar provides explicit Save and Unlock actions for this MLS
  state. The password input is zeroized after each operation; a zeroizing
  in-memory copy remains available while inbound safe-save is active. The location is
  `nyx-desktop-state.nyx` or `NYX_DESKTOP_STATE_PATH` when configured.
- The workspace currently has twenty-two store/crypto/transport/mailbox/protocol/UI unit tests
  covering MLS group/Welcome/message processing, replay rejection, device
  material validation, request serialization,
  oversized-frame rejection, receipt binding, mailbox lifecycle, cross-mailbox
  ACK isolation, Onion endpoint validation, snapshot v1 migration, and invalid input rejection.

## Not implemented

- General group lifecycle operations, remote commit handling, removals, and
  updates are not implemented. Without an explicit Unlock action, the current
  two-member demo conversation is recreated on app start.
- Device identity generation, contact invitations, out-of-band verification,
  and multi-device behavior are not implemented.
- Initial persistence and outbound ratchet persistence are still manual; inbound
  processing is automatically safe-saved after Save or Unlock. There is no password
  strength meter, operating-system keyring integration, or recovery mechanism.
  Displayed UI history is not part of the MLS snapshot.
- The generic client SQLite `kv` store remains unencrypted and must not hold
  secrets.
- Attachment transfer, padding buckets, batching, cover traffic, token
  rotation, bounded retry backoff, encrypted ACK payloads, and optional direct
  peer Onion Services are not implemented. The current worker retries at a
  fixed ten-second interval.
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
- The MLS snapshot currently mirrors OpenMLS MemoryStorage's internal key/value
  representation. It is versioned by Nyx but still needs explicit migration
  tests before OpenMLS dependency upgrades.

## Verified in this revision

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

All commands pass. A successful compile and unit-test run does not verify
publication or reachability on the public Tor network.

## Next milestone

The next useful milestone is coordinated safe-save for outbound ratchet
advancement and queue insertion. The manual live-Tor smoke test should later
become an isolated, opt-in CI job.

## Resume notes

Start with outbound safe-save coordination.
The desktop transport configuration is:

```bash
export NYX_MAILBOX_ONION="<v3-address>.onion"
export NYX_MAILBOX_PORT="443"
export NYX_RECIPIENT_MAILBOX_TOKEN_HEX="<64 hexadecimal characters>"
export NYX_LOCAL_MAILBOX_TOKEN_HEX="<64 hexadecimal characters>"
cd apps/desktop
dx serve --desktop
```

Do not test with sensitive messages. A live public-Tor integration run still
requires an explicitly started mailbox server and has not been completed for
this revision.
