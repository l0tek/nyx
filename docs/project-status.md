# Nyx project status

Status date: 2026-08-28

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

- The shared Dioxus desktop/Android app now starts with a compact status view
  and provides navigation through the native Dioxus menu, including back and
  forward controls. Local registration and password login remain available.
  This is an encrypted on-device profile, not a central account: no e-mail,
  telephone number, directory username, or authentication server is involved.
- Meshtastic integration is available as an additional local radio transport.
  Linux, Windows, and macOS use the official Rust `meshtastic` crate over
  USB-Serial at 115200 baud. Android uses a native Kotlin/JNI Bluetooth Low
  Energy plugin and the official Meshtastic GATT service UUID; Android does not
  expose the USB transport.
- The configuration screen can scan for serial/BLE devices, select a discovered
  device from a drop-down or accept a manually entered port/address, connect,
  disconnect, and report connection errors. The main status screen always shows
  Meshtastic state and links directly to its setup.
- The selected Meshtastic USB port or BLE address is persisted locally and
  restored on the next client start. Desktop uses the stable operating-system
  configuration directory rather than the process working directory. Desktop
  also shows a bounded startup progress screen while local stores are prepared.
- A configured desktop radio reports the local Meshtastic node ID, node name,
  hardware model, NodeDB size, battery, voltage, channel utilization, firmware
  environment, selected port, and observed PhoneAPI packet count when supplied
  by the firmware.
- Outbound delivery now follows a Tor-first policy. Only after Tor bootstrap,
  Onion health, or mailbox deposit fails does the worker offer pending, already
  MLS-encrypted client payloads to an active Meshtastic USB session. A verified
  contact can store an optional hexadecimal Meshtastic node ID; queued payloads
  are routed by the contact's mailbox capability to that per-contact node.
- The experimental Meshtastic fallback uses `PRIVATE_APP`, unicast packets and
  per-fragment `want_ack`. A versioned `NYXM` envelope carries the stable queue
  UUID, fragment index/count, and a truncated BLAKE3 whole-message digest.
  Payloads are split below Meshtastic's 233-byte application limit and capped at
  16 KiB. Unit tests verify bounds, stable identity, and invalid-size rejection.
- The status screen can send a `PRIVATE_APP` test packet to the Meshtastic node
  stored on the selected verified contact. Desktop uses USB StreamAPI; Android
  encodes `ToRadio` and writes it to the official GATT characteristic.
- Dispatching fragments to a radio deliberately does not mark the durable Tor
  queue item delivered. A radio ACK is not proof that the peer reassembled and
  committed the MLS message. Tor therefore remains eligible to retry, while MLS
  replay rejection protects against a later duplicate.
- A persistent device identity contains a separate Ed25519 invitation-signing
  key, stable device UUID, OpenMLS signing material/provider state, a validated
  RFC 9420 KeyPackage, contacts, and outstanding directional capabilities. It is
  stored with the authenticated encrypted blob format.
- The app exposes the device fingerprint, signed contact invitation generation,
  invitation import, contact selection, explicit out-of-band fingerprint
  verification, account locking, and mailbox connection state in a revised UI.
  Contact invitations can be exported as a visible QR code on desktop and
  Android. Android can scan the same signed contact QR invitation with its
  camera; this is contact exchange only and does not export the local identity.
- Android uses a status header with back/forward navigation and a hamburger
  drawer containing configuration, contact import/export, and imported contacts.
  Successful import opens the contact verification screen directly. A confirmed
  reconnect action can remove an obsolete contact and local MLS session before
  importing a replacement invitation.
- Configuration is available from the Dioxus menu. The bundled default mailbox
  Onion address is shown there and can be edited; additional mailbox entries can
  be added, selected, changed, and persisted locally on desktop and Android.
- Mailbox removal is address-based rather than dependent on a stale UI list
  index, and the final active mailbox cannot be removed.
- Saving configuration provides pressed-state/haptic feedback and a visible
  result. Changing the active Onion address interrupts the polling delay within
  100 ms and immediately checks the newly selected mailbox.
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
- The client owns an asynchronous worker that validates the selected mailbox,
  bootstraps Tor without a Clearnet fallback, flushes every ten seconds, keeps
  failures queued, and reports bootstrap/delivery/retry state. Arti client state
  and cache are placed below the application data directory so Android does not
  depend on an unavailable process working directory during bootstrap.
- The worker restores receive capabilities for every contact and every issued
  invitation, reads them directly from the unlocked encrypted identity on each
  cycle, and prioritizes recent invitations. Application messages without an
  established remote session remain unacknowledged while contact handshakes are
  sought in the other inboxes.
- Displayed messages carry a contact device ID; the chat view filters them by
  the selected contact instead of mixing all conversations into one timeline.
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
- The workspace test suite covers store/crypto/transport/mailbox/protocol/UI
  behavior including MLS group/Welcome/message processing, replay rejection, device
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
- The mailbox server supports deliberate Onion identity reinitialization with
  `--reinitialize-onion-identity` or
  `NYX_MAILBOX_REINITIALIZE_ONION_IDENTITY=1`. The old Arti state is renamed to
  a timestamped backup while `mailbox.sqlite3` is preserved; operators must
  then update the expected address and all clients.
- Android QR scanning depends on camera permission and the system WebView's
  `BarcodeDetector` QR support. Device-level camera scanning and Tor bootstrap
  still require acceptance testing on representative Android versions.
- Meshtastic inbound `NYXM` reassembly, end-to-end fallback receipts, selective
  missing-fragment retransmission, durable fragment state, Android BLE payload
  transfer, and authenticated automatic peer-node discovery are not
  implemented. Until those pieces exist, the current Tor-first Meshtastic path
  is an experimental outbound dispatch mechanism, not a complete alternative
  delivery channel. Initial MLS Welcome/KeyPackage transfer and large files
  remain Tor/QR-only. No radio hardware interoperability test has been run.

## Current live integration status

- The receive worker no longer lets a stale, malformed, or otherwise rejected
  item in one capability stop polling every remaining contact inbox. This was
  able to starve a valid `InvitationAcceptance` in a later inbox indefinitely,
  leaving its subsequent `MlsApplication` payloads without an established MLS
  session.
- Privacy-safe debug tracing now reports only inbox position, item count, and
  payload kind. It never logs mailbox capabilities, receipts, sender IDs, or
  message contents. The Android-to-desktop flow still needs a confirming run on
  the public Tor test setup.

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
- Meshtastic exposes radio node identifiers, timing, packet counts, approximate
  message size, and RF topology even though the application body remains MLS
  ciphertext. Meshtastic channel or PKI encryption is defense in depth and is
  never trusted as a replacement for MLS authentication. The default public
  LongFast channel is inappropriate for sensitive traffic.
- The official Rust Meshtastic dependency is GPL-3.0. Distribution of linked
  desktop binaries requires a license-compliance decision for the combined work.

## Verified in this revision

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace
```

All commands pass, including 43 workspace tests. A successful compile and unit-test run does not verify
publication or reachability on the public Tor network.

The desktop client was also connected to a real HELTEC_V3 over `/dev/ttyUSB0`
and detected local node `!9e76506c`. Meshtastic test packets now wait for
firmware routing acknowledgements instead of reporting success immediately
after the local serial write. Android BLE serializes GATT reads and writes so a
periodic `FromRadio` read cannot cause `ToRadio` to be rejected as busy.

The current end-to-end test to node `!9e7638c4` returns `NO_CHANNEL`. The radio
transport and acknowledgement path are therefore working, but the receiving
node cannot decrypt the direct packet. Before resuming code work, verify a
shared primary-channel PSK, refresh both nodes' NodeDB/public-key entries, and
confirm a direct message in the official Meshtastic client.

Desktop Linux and Android debug packages were also built in this revision. The
Android package contains both `arm64-v8a` and `x86_64` native libraries. Generated
packages live under the ignored `dist/` directory and are not part of Git.
Use `scripts/build-android.sh` for universal APKs. It explicitly rebuilds both
architectures and packages the Dioxus-provided OpenSSL libraries required by
Arti; invoking separate `dx build --target` commands without that final packaging
step can create an APK that crashes at startup because `libssl.so` is absent.

## Next milestone

The immediate Meshtastic milestone is implementing authenticated inbound
fragment reassembly and an MLS-processing receipt before allowing a successful
radio fallback to retire a Tor queue item. Selective retransmission, durable
partial state, verified contact-to-node binding, and Android BLE payload transfer
follow. The Tor milestone remains confirming Android-to-desktop invitation flow
on the public test setup and converting it into an isolated live integration test.

## Resume notes

Confirm the Android-to-desktop acceptance with privacy-safe per-inbox
payload-kind tracing enabled. Do not delete the queued mailbox rows before that
run. Then continue with encrypted per-contact history and remote MLS commit
lifecycle handling.
The legacy environment-based desktop transport configuration is:

```bash
export NYX_MAILBOX_ONION="<v3-address>.onion"
export NYX_MAILBOX_PORT="443"
export NYX_RECIPIENT_MAILBOX_TOKEN_HEX="<64 hexadecimal characters>"
export NYX_LOCAL_MAILBOX_TOKEN_HEX="<64 hexadecimal characters>"
# Store !a1b2c3d4 on the verified contact in the Nyx contact view.
cd apps/desktop
dx serve --desktop
```

Do not test with sensitive messages. A live public-Tor integration run still
requires an explicitly started mailbox server and has not been completed for
this revision.
