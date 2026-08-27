use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const MAX_CIPHERTEXT_SIZE: usize = MAX_FRAME_SIZE - 1024;
pub const MAX_FETCH_MESSAGES: u16 = 128;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub version: u16,
    pub mailbox_token: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Request sent over an end-to-end Tor onion-service stream.
///
/// Tokens and receipts are opaque capabilities. They must never be logged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailboxRequest {
    Deposit(Envelope),
    Fetch {
        mailbox_token: [u8; 32],
        limit: u16,
    },
    Acknowledge {
        mailbox_token: [u8; 32],
        receipts: Vec<[u8; 32]>,
    },
    Health {
        version: u16,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredEnvelope {
    pub receipt: [u8; 32],
    pub envelope: Envelope,
    pub expires_unix_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MailboxResponse {
    Deposited { receipt: [u8; 32] },
    Messages(Vec<StoredEnvelope>),
    Acknowledged { deleted: u16 },
    Ready { version: u16 },
    Error(MailboxErrorCode),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MailboxErrorCode {
    InvalidVersion,
    InvalidLimit,
    MessageTooLarge,
    MalformedRequest,
    ServerBusy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub message_id: Uuid,
    pub conversation_id: Uuid,
    pub sender_device: Uuid,
    pub timestamp_ms: i64,
    pub content_type: ContentType,
    pub content: Vec<u8>,
    pub reply_to: Option<Uuid>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ContentType {
    Text,
    AttachmentDescriptor,
    Receipt,
    Control,
}

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("serialization failed")]
    Serialization,
    #[error("frame exceeds the maximum size")]
    FrameTooLarge,
}

pub fn encode_envelope(value: &Envelope) -> Result<Vec<u8>, ProtocolError> {
    postcard::to_allocvec(value).map_err(|_| ProtocolError::Serialization)
}

pub fn decode_envelope(bytes: &[u8]) -> Result<Envelope, ProtocolError> {
    postcard::from_bytes(bytes).map_err(|_| ProtocolError::Serialization)
}

pub fn encode_request(value: &MailboxRequest) -> Result<Vec<u8>, ProtocolError> {
    encode_frame(value)
}

pub fn decode_request(bytes: &[u8]) -> Result<MailboxRequest, ProtocolError> {
    decode_frame(bytes)
}

pub fn encode_response(value: &MailboxResponse) -> Result<Vec<u8>, ProtocolError> {
    encode_frame(value)
}

pub fn decode_response(bytes: &[u8]) -> Result<MailboxResponse, ProtocolError> {
    decode_frame(bytes)
}

/// Stable opaque identifier used to acknowledge one stored ciphertext.
pub fn envelope_receipt(envelope: &Envelope) -> Result<[u8; 32], ProtocolError> {
    let encoded = encode_envelope(envelope)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn encode_frame<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes = postcard::to_allocvec(value).map_err(|_| ProtocolError::Serialization)?;
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge);
    }
    Ok(bytes)
}

fn decode_frame<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, ProtocolError> {
    if bytes.len() > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge);
    }
    postcard::from_bytes(bytes).map_err(|_| ProtocolError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_request_round_trip() {
        let request = MailboxRequest::Fetch {
            mailbox_token: [7; 32],
            limit: 10,
        };
        let decoded = decode_request(&encode_request(&request).unwrap()).unwrap();
        assert!(matches!(decoded, MailboxRequest::Fetch { limit: 10, .. }));
    }

    #[test]
    fn health_request_round_trip() {
        let request = MailboxRequest::Health {
            version: PROTOCOL_VERSION,
        };
        let decoded = decode_request(&encode_request(&request).unwrap()).unwrap();
        assert!(matches!(
            decoded,
            MailboxRequest::Health {
                version: PROTOCOL_VERSION
            }
        ));
    }

    #[test]
    fn oversized_frame_is_rejected_before_deserialization() {
        let bytes = vec![0; MAX_FRAME_SIZE + 1];
        assert!(matches!(
            decode_request(&bytes),
            Err(ProtocolError::FrameTooLarge)
        ));
    }

    #[test]
    fn receipt_is_stable_and_content_bound() {
        let mut envelope = Envelope {
            version: PROTOCOL_VERSION,
            mailbox_token: [1; 32],
            ciphertext: vec![2, 3],
        };
        let first = envelope_receipt(&envelope).unwrap();
        assert_eq!(first, envelope_receipt(&envelope).unwrap());
        envelope.ciphertext.push(4);
        assert_ne!(first, envelope_receipt(&envelope).unwrap());
    }
}
