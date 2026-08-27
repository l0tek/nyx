//! Cryptographic boundary.
//!
//! Production implementation must use OpenMLS for session/group E2EE.
//! Do not invent a custom ratchet or key-exchange protocol here.

use anyhow::{Result, bail};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NYX_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_DEVICE_IDENTITY_SIZE: usize = 1024;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalSecret(pub Vec<u8>);

pub struct CryptoEngine;

/// Volatile OpenMLS device material used as the basis for group creation.
///
/// The provider and signer are intentionally kept private. Production use must
/// add encrypted persistence before this material is used for real identities.
pub struct MlsDevice {
    provider: OpenMlsRustCrypto,
    signer: SignatureKeyPair,
    credential: CredentialWithKey,
    key_package: KeyPackageBundle,
}

impl MlsDevice {
    pub fn generate(identity: impl Into<Vec<u8>>) -> Result<Self> {
        let identity = identity.into();
        if identity.is_empty() {
            bail!("MLS device identity must not be empty");
        }
        if identity.len() > MAX_DEVICE_IDENTITY_SIZE {
            bail!("MLS device identity exceeds maximum size");
        }

        let provider = OpenMlsRustCrypto::default();
        let signer = SignatureKeyPair::new(NYX_CIPHERSUITE.signature_algorithm())
            .map_err(|error| anyhow::anyhow!("generate MLS signature key: {error:?}"))?;
        signer
            .store(provider.storage())
            .map_err(|error| anyhow::anyhow!("store MLS signature key: {error:?}"))?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let key_package = KeyPackage::builder()
            .build(NYX_CIPHERSUITE, &provider, &signer, credential.clone())
            .map_err(|error| anyhow::anyhow!("build MLS key package: {error:?}"))?;

        Ok(Self {
            provider,
            signer,
            credential,
            key_package,
        })
    }

    pub fn credential(&self) -> &CredentialWithKey {
        &self.credential
    }

    pub fn key_package(&self) -> &KeyPackageBundle {
        &self.key_package
    }

    pub fn provider(&self) -> &OpenMlsRustCrypto {
        &self.provider
    }

    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_device_credential_and_key_package() {
        let device = MlsDevice::generate(b"device-1".to_vec()).unwrap();
        assert_eq!(
            device.key_package().key_package().ciphersuite(),
            NYX_CIPHERSUITE
        );
        assert!(!device.credential().signature_key.as_slice().is_empty());
    }

    #[test]
    fn rejects_invalid_device_identity() {
        assert!(MlsDevice::generate(Vec::new()).is_err());
        assert!(MlsDevice::generate(vec![0; MAX_DEVICE_IDENTITY_SIZE + 1]).is_err());
    }
}
