use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use uuid::Uuid;

const MAGIC: &[u8; 4] = b"NYXM";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 16 + 2 + 2 + 8;
const MAX_MESH_PAYLOAD: usize = 233;
const FRAGMENT_DATA_LEN: usize = MAX_MESH_PAYLOAD - HEADER_LEN;
const MAX_MESSAGE_LEN: usize = 16 * 1024;
const RECEIPT_MAGIC: &[u8; 4] = b"NYXR";
const RECEIPT_LEN: usize = 4 + 1 + 16 + 8 + 64;
const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_PARTIAL_MESSAGES: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum MeshFrame {
    Fragment(Fragment),
    Receipt {
        id: Uuid,
        digest: [u8; 8],
        signature: [u8; 64],
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Fragment {
    id: Uuid,
    index: u16,
    count: u16,
    digest: [u8; 8],
    payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct CompleteMessage {
    pub id: Uuid,
    pub digest: [u8; 8],
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub(super) enum InboundEvent {
    Message {
        source: u32,
        id: Uuid,
        digest: [u8; 8],
        payload: Vec<u8>,
    },
    Receipt {
        source: u32,
        id: Uuid,
        digest: [u8; 8],
        signature: [u8; 64],
    },
}

struct PartialMessage {
    digest: [u8; 8],
    fragments: Vec<Option<Vec<u8>>>,
    received_len: usize,
    updated: Instant,
}

#[derive(Default)]
pub(super) struct Reassembler {
    partial: HashMap<(u32, Uuid), PartialMessage>,
}

pub(super) fn fragment(id: Uuid, ciphertext: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if ciphertext.is_empty() || ciphertext.len() > MAX_MESSAGE_LEN {
        return Err(format!(
            "Meshtastic fallback accepts 1..={MAX_MESSAGE_LEN} bytes"
        ));
    }
    let count = ciphertext.len().div_ceil(FRAGMENT_DATA_LEN);
    let count = u16::try_from(count).map_err(|_| "too many Meshtastic fragments")?;
    let digest = blake3::hash(ciphertext);
    ciphertext
        .chunks(FRAGMENT_DATA_LEN)
        .enumerate()
        .map(|(index, chunk)| {
            let mut output = Vec::with_capacity(HEADER_LEN + chunk.len());
            output.extend_from_slice(MAGIC);
            output.push(VERSION);
            output.extend_from_slice(id.as_bytes());
            output.extend_from_slice(&(index as u16).to_be_bytes());
            output.extend_from_slice(&count.to_be_bytes());
            output.extend_from_slice(&digest.as_bytes()[..8]);
            output.extend_from_slice(chunk);
            Ok(output)
        })
        .collect()
}

pub(super) fn receipt(id: Uuid, digest: [u8; 8], signature: [u8; 64]) -> Vec<u8> {
    let mut output = Vec::with_capacity(RECEIPT_LEN);
    output.extend_from_slice(RECEIPT_MAGIC);
    output.push(VERSION);
    output.extend_from_slice(id.as_bytes());
    output.extend_from_slice(&digest);
    output.extend_from_slice(&signature);
    output
}

pub(super) fn parse(bytes: &[u8]) -> Result<MeshFrame, String> {
    if bytes.len() == RECEIPT_LEN && bytes.starts_with(RECEIPT_MAGIC) {
        if bytes[4] != VERSION {
            return Err("unsupported Meshtastic receipt version".into());
        }
        let id = Uuid::from_slice(&bytes[5..21]).map_err(|_| "invalid Meshtastic receipt id")?;
        let digest = bytes[21..29]
            .try_into()
            .map_err(|_| "invalid Meshtastic receipt digest")?;
        let signature = bytes[29..93]
            .try_into()
            .map_err(|_| "invalid Meshtastic receipt signature")?;
        return Ok(MeshFrame::Receipt {
            id,
            digest,
            signature,
        });
    }
    if bytes.len() <= HEADER_LEN || !bytes.starts_with(MAGIC) {
        return Err("not a NYX Meshtastic frame".into());
    }
    if bytes[4] != VERSION {
        return Err("unsupported Meshtastic fragment version".into());
    }
    let id = Uuid::from_slice(&bytes[5..21]).map_err(|_| "invalid Meshtastic message id")?;
    let index = u16::from_be_bytes(
        bytes[21..23]
            .try_into()
            .map_err(|_| "invalid fragment index")?,
    );
    let count = u16::from_be_bytes(
        bytes[23..25]
            .try_into()
            .map_err(|_| "invalid fragment count")?,
    );
    if count == 0 || usize::from(index) >= usize::from(count) {
        return Err("invalid Meshtastic fragment position".into());
    }
    let digest = bytes[25..33]
        .try_into()
        .map_err(|_| "invalid fragment digest")?;
    Ok(MeshFrame::Fragment(Fragment {
        id,
        index,
        count,
        digest,
        payload: bytes[HEADER_LEN..].to_vec(),
    }))
}

impl Reassembler {
    pub(super) fn push(
        &mut self,
        source: u32,
        bytes: &[u8],
    ) -> Result<Option<CompleteMessage>, String> {
        self.partial
            .retain(|_, value| value.updated.elapsed() < REASSEMBLY_TIMEOUT);
        let MeshFrame::Fragment(fragment) = parse(bytes)? else {
            return Err("receipt cannot be reassembled as a message".into());
        };
        let key = (source, fragment.id);
        if !self.partial.contains_key(&key) && self.partial.len() >= MAX_PARTIAL_MESSAGES {
            return Err("too many incomplete Meshtastic messages".into());
        }
        let partial = self.partial.entry(key).or_insert_with(|| PartialMessage {
            digest: fragment.digest,
            fragments: (0..fragment.count).map(|_| None).collect(),
            received_len: 0,
            updated: Instant::now(),
        });
        if partial.digest != fragment.digest
            || partial.fragments.len() != usize::from(fragment.count)
        {
            self.partial.remove(&key);
            return Err("inconsistent Meshtastic fragment metadata".into());
        }
        let slot = &mut partial.fragments[usize::from(fragment.index)];
        if let Some(existing) = slot {
            if existing != &fragment.payload {
                self.partial.remove(&key);
                return Err("conflicting duplicate Meshtastic fragment".into());
            }
            return Ok(None);
        }
        partial.received_len = partial.received_len.saturating_add(fragment.payload.len());
        if partial.received_len > MAX_MESSAGE_LEN {
            self.partial.remove(&key);
            return Err("reassembled Meshtastic message exceeds maximum size".into());
        }
        *slot = Some(fragment.payload);
        partial.updated = Instant::now();
        if partial.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }
        let complete = self
            .partial
            .remove(&key)
            .ok_or_else(|| "Meshtastic reassembly state disappeared".to_owned())?;
        let payload = complete
            .fragments
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>();
        let actual = blake3::hash(&payload);
        if actual.as_bytes()[..8] != complete.digest {
            return Err("Meshtastic message digest mismatch".into());
        }
        Ok(Some(CompleteMessage {
            id: fragment.id,
            digest: complete.digest,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fragments_stay_within_meshtastic_limit_and_share_identity() {
        let id = Uuid::new_v4();
        let fragments = fragment(id, &vec![7; 1000]).unwrap();
        assert!(fragments.len() > 1);
        assert!(
            fragments
                .iter()
                .all(|fragment| fragment.len() <= MAX_MESH_PAYLOAD)
        );
        assert!(fragments.iter().all(|fragment| &fragment[..4] == MAGIC));
        assert!(
            fragments
                .iter()
                .all(|fragment| &fragment[5..21] == id.as_bytes())
        );
    }

    #[test]
    fn rejects_empty_and_oversized_messages() {
        assert!(fragment(Uuid::new_v4(), &[]).is_err());
        assert!(fragment(Uuid::new_v4(), &vec![0; MAX_MESSAGE_LEN + 1]).is_err());
    }

    #[test]
    fn reassembles_out_of_order_and_parses_receipt() {
        let id = Uuid::new_v4();
        let payload = vec![9; 700];
        let mut fragments = fragment(id, &payload).unwrap();
        fragments.reverse();
        let mut reassembler = Reassembler::default();
        let mut complete = None;
        for fragment in fragments {
            complete = reassembler.push(42, &fragment).unwrap().or(complete);
        }
        let complete = complete.unwrap();
        assert_eq!(complete.payload, payload);
        let signature = [3; 64];
        assert_eq!(
            parse(&receipt(id, complete.digest, signature)).unwrap(),
            MeshFrame::Receipt {
                id,
                digest: complete.digest,
                signature,
            }
        );
    }

    #[test]
    fn rejects_conflicting_fragment_metadata() {
        let id = Uuid::new_v4();
        let fragments = fragment(id, &vec![1; 500]).unwrap();
        let mut conflicting = fragments[1].clone();
        conflicting[25] ^= 1;
        let mut reassembler = Reassembler::default();
        assert!(reassembler.push(7, &fragments[0]).unwrap().is_none());
        assert!(reassembler.push(7, &conflicting).is_err());
    }
}
