use uuid::Uuid;

const MAGIC: &[u8; 4] = b"NYXM";
const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 16 + 2 + 2 + 8;
const MAX_MESH_PAYLOAD: usize = 233;
const FRAGMENT_DATA_LEN: usize = MAX_MESH_PAYLOAD - HEADER_LEN;
const MAX_MESSAGE_LEN: usize = 16 * 1024;

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
}
