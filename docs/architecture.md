# Nyx Architecture

## Trust split

Tor protects transport anonymity and endpoint addressing. MLS protects message confidentiality/authenticity. The mailbox server is not trusted with plaintext or social-graph data.

```text
Dioxus UI
   |
Application Core
   |---- Identity / Contacts
   |---- Crypto boundary (OpenMLS)
   |---- Local encrypted store
   |---- Message queue / ACK / retry
   |
Tor transport boundary (Arti)
   |
   +---- Mailbox Onion Service
   |
   +---- Optional direct peer Onion Service
```

## Envelope

Outer transport object:

```text
Envelope {
    version,
    mailbox_token,
    ciphertext,
}
```

Encrypted inner object:

```text
EncryptedMessage {
    message_id,
    conversation_id,
    sender_device,
    timestamp,
    content_type,
    content,
    reply_to,
    attachment_descriptor,
}
```

## MVP sequence

1. Bootstrap Tor via Arti.
2. Create/import local identity.
3. Exchange verified contact invitation out of band.
4. Establish 1:1 MLS group/session.
5. Serialize encrypted message into a padded envelope.
6. Upload envelope to mailbox `.onion` endpoint.
7. Recipient polls pseudonymous mailbox token via Tor.
8. Recipient decrypts locally and sends encrypted/opaque ACK.
9. Server deletes acknowledged or expired ciphertext.

## High-security extensions

- rotating mailbox tokens by epoch.
- fixed-size text frames.
- batched mailbox polling.
- optional cover traffic.
- Onion client authorization for private services.
- multiple independent mailbox providers.
- direct Onion peer sessions when both peers are online.
