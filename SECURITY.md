# Nyx Security Policy

## Non-negotiable rules

1. Never implement custom cryptographic primitives.
2. Never fall back to direct/Clearnet transport when Tor is unavailable.
3. Never log message plaintext, secret keys, recovery material or unredacted Onion credentials.
4. Treat message size, timing and mailbox access patterns as metadata leakage.
5. Pin and audit security-critical dependencies before release.
6. Disable crypto/content debug features in production builds.
7. Require out-of-band contact verification for high-security conversations.
8. Separate identity keys from transport/Onion-service keys.
9. Rotate delivery tokens and expire undelivered ciphertext.
10. Obtain an independent security audit before any claim of "secure" or "anonymous" production use.

## Release gate

- `cargo audit` clean or explicitly reviewed.
- dependency lockfile reviewed.
- fuzz tests for frame parser.
- malformed-message tests.
- no panic on untrusted network input.
- no Clearnet sockets in Tor-only mode.
- log redaction verified.
- local database encryption verified.
- key deletion/zeroization behavior reviewed.
