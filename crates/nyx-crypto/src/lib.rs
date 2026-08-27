//! Cryptographic boundary.
//!
//! Production implementation must use OpenMLS for session/group E2EE.
//! Do not invent a custom ratchet or key-exchange protocol here.

use anyhow::{Result, bail};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalSecret(pub Vec<u8>);

pub struct CryptoEngine;

impl CryptoEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn encrypt_application_message(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        bail!("OpenMLS integration not implemented in scaffold")
    }

    pub fn decrypt_application_message(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        bail!("OpenMLS integration not implemented in scaffold")
    }
}

impl Default for CryptoEngine {
    fn default() -> Self {
        Self::new()
    }
}
