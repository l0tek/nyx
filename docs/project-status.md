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
  acknowledging opaque envelopes, plus a payload-free protocol-version health
  check that reveals no mailbox capability.
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

- The Dioxus desktop app now starts with local registration or password login.
  This is an encrypted on-device profile, not a central account: no e-mail,
  telephone number, directory username, or authentication server is involved.
- A persistent device identity contains a separate Ed25519 invitation-signing
  key, stable device UUID, OpenMLS signing material/provider state, a validated
  RFC 9420 KeyPackage, contacts, and outstanding directional capabilities. It is
  stored with the authenticated encrypted blob format.
- The desktop exposes the device fingerprint, signed invitation generation,
  invitation import, contact selection, explicit out-of-band fingerprint
  verification, account locking, and the mailbox connection state in a revised UI.
- Contact invitations are URL-safe Base64/Postcard objects signed over all
  fields. Import verifies the Ed25519 signature, timestamps, v3 Onion syntax,
  MLS KeyPackage signature/lifetime/ciphersuite, duplicate device IDs, and size
  bounds. Each invitation contains separate random 256-bit capabilities for
  inviter-bound and invitee-bound traffic.
- A verified contact can now accept an invitation in the desktop UI. The
  accepting device creates a real two-member OpenMLS group, adds the inviter's
  persisted KeyPackage, merges the Add commit, and signs a response containing
  the MLS Welcome with its persistent Ed25519 device identity.
- The invitation acceptance and subsequent MLS application messages use a
  typed client-to-client payload which remains opaque to the mailbox server.
  The inviter verifies the acceptance signature, matches it to an outstanding
  invitation, creates the reverse directional contact, and joins the group
  from the Welcome using its persisted private KeyPackage material.
- Remote 1:1 group identifiers and complete OpenMLS provider state are stored
  in the encrypted device identity. The desktop shows whether the selected
  contact has an active MLS session and enables messaging only after both
  fingerprint verification and session establishment.
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
- Before an outbound message enters SQLite, the advanced MLS ratchets, stable
  queue UUID, recipient mailbox token, and ciphertext are atomically saved in
  the encrypted vault. SQLite insertion is idempotent; a crash before or after
  insertion is recovered from the vault journal without duplicating the queue
  item. The journal entry is removed only after SQLite accepts the same UUID and
  payload.
- The same encrypted-journal handoff now protects signed Welcome responses and
  remote-contact messages. Remote inbound receipt journals are persisted with
  the advanced ratchet before mailbox acknowledgement, so an ACK retry does not
  replay an MLS PrivateMessage.
- `nyx-tor` can flush queued envelopes in order, record an attempt before each
  request, and mark delivery only after the Onion mailbox confirms deposit.
- The desktop owns an asynchronous worker that validates `NYX_MAILBOX_ONION`,
  bootstraps Tor without a Clearnet fallback, flushes every ten seconds, keeps
  failures queued, and reports bootstrap/delivery/retry state in the sidebar.
- The sidebar exposes structured connection state for Tor bootstrap and Onion
  mailbox reachability, the configured endpoint, health-check latency, delivery
  detail, and time since the last successful mailbox check. A failed health check
  prevents deposit/fetch work for that cycle and is retried after ten seconds.
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
- Login unlocks both device identity and MLS state with one local vault password.
  The input is zeroized after each attempt; a zeroizing in-memory copy remains
  available while safe-save is active. Identity defaults to
  `nyx-device-identity.nyx` (`NYX_DEVICE_IDENTITY_PATH`), while MLS state remains
  `nyx-desktop-state.nyx` (`NYX_DESKTOP_STATE_PATH`).
- The workspace currently has thirty-five store/crypto/transport/mailbox/protocol/UI unit tests
  covering MLS group/Welcome/message processing, replay rejection, device
  material validation, request serialization,
  oversized-frame rejection, receipt binding, mailbox lifecycle, cross-mailbox
  ACK isolation, Onion endpoint validation, snapshot v1/v2 migration, idempotent
  queue handoff, inbound/outbound safe-save rollback, legacy response-discriminant
  compatibility, persistent identity reload, signed invitation tamper rejection,
  MLS KeyPackage validation, directional token mapping, signed acceptance,
  bidirectional remote MLS exchange, and invalid input rejection.

## Not implemented

- General group lifecycle operations, remote commit handling, removals, updates,
  KeyPackage rotation, invitation revocation, and multi-device behavior are not implemented.
- Initial persistence is still manual; inbound and configured outbound processing
  are automatically safe-saved after Save or Unlock. There is no password
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

The next useful milestone is durable encrypted message history plus MLS update,
removal, and KeyPackage-rotation handling. A two-desktop live-Tor acceptance and
chat scenario should also become an isolated, opt-in integration test.

## Resume notes

Start with encrypted per-contact history and remote MLS commit lifecycle handling.
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
