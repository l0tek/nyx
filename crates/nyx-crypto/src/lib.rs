//! Cryptographic boundary.
//!
//! Production implementation must use OpenMLS for session/group E2EE.
//! Do not invent a custom ratchet or key-exchange protocol here.

use anyhow::{Result, bail};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, StagedWelcome, tls_codec::Deserialize,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NYX_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_DEVICE_IDENTITY_SIZE: usize = 1024;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct LocalSecret(pub Vec<u8>);

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

/// A local two-member MLS conversation used by the current MVP.
///
/// It performs the real OpenMLS add/Welcome flow. Persistence and transport of
/// the Welcome/commit are separate application-layer responsibilities.
pub struct MlsConversation {
    alice: MlsDevice,
    bob: MlsDevice,
    alice_group: MlsGroup,
    bob_group: MlsGroup,
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

impl MlsConversation {
    pub fn new_1to1(alice_identity: Vec<u8>, bob_identity: Vec<u8>) -> Result<Self> {
        let alice = MlsDevice::generate(alice_identity)?;
        let bob = MlsDevice::generate(bob_identity)?;
        let create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(NYX_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let mut alice_group = MlsGroup::new(
            alice.provider(),
            alice.signer(),
            &create_config,
            alice.credential().clone(),
        )
        .map_err(|error| anyhow::anyhow!("create MLS group: {error:?}"))?;

        let (_, welcome, _) = alice_group
            .add_members(
                alice.provider(),
                alice.signer(),
                &[bob.key_package().key_package().clone()],
            )
            .map_err(|error| anyhow::anyhow!("add MLS group member: {error:?}"))?;
        alice_group
            .merge_pending_commit(alice.provider())
            .map_err(|error| anyhow::anyhow!("merge MLS add commit: {error:?}"))?;

        let welcome_bytes = welcome
            .to_bytes()
            .map_err(|error| anyhow::anyhow!("serialize MLS Welcome: {error:?}"))?;
        let welcome = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|error| anyhow::anyhow!("deserialize MLS Welcome: {error:?}"))?;
        let MlsMessageBodyIn::Welcome(welcome) = welcome.extract() else {
            bail!("OpenMLS did not produce a Welcome message");
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let bob_group =
            StagedWelcome::new_from_welcome(bob.provider(), &join_config, welcome, None)
                .map_err(|error| anyhow::anyhow!("process MLS Welcome: {error:?}"))?
                .into_group(bob.provider())
                .map_err(|error| anyhow::anyhow!("join MLS group: {error:?}"))?;

        if alice_group.epoch_authenticator().as_slice()
            != bob_group.epoch_authenticator().as_slice()
        {
            bail!("MLS members derived different epoch authenticators");
        }

        Ok(Self {
            alice,
            bob,
            alice_group,
            bob_group,
        })
    }

    pub fn encrypt_from_alice(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("MLS application message must not be empty");
        }
        self.alice_group
            .create_message(self.alice.provider(), self.alice.signer(), plaintext)
            .map_err(|error| anyhow::anyhow!("encrypt MLS application message: {error:?}"))?
            .to_bytes()
            .map_err(|error| anyhow::anyhow!("serialize MLS application message: {error:?}"))
    }

    pub fn decrypt_for_bob(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| anyhow::anyhow!("deserialize MLS message: {error:?}"))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|error| anyhow::anyhow!("expected an MLS protocol message: {error:?}"))?;
        let processed = self
            .bob_group
            .process_message(self.bob.provider(), protocol_message)
            .map_err(|error| anyhow::anyhow!("decrypt MLS application message: {error:?}"))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            _ => bail!("received MLS message is not application data"),
        }
    }

    pub fn round_trip_from_alice(&mut self, plaintext: &[u8]) -> Result<(usize, Vec<u8>)> {
        let ciphertext = self.encrypt_from_alice(plaintext)?;
        let ciphertext_size = ciphertext.len();
        let decrypted = self.decrypt_for_bob(&ciphertext)?;
        Ok((ciphertext_size, decrypted))
    }

    pub fn member_count(&self) -> usize {
        self.alice_group.members().count()
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

    #[test]
    fn creates_group_from_welcome_and_exchanges_application_message() {
        let mut conversation =
            MlsConversation::new_1to1(b"alice-device".to_vec(), b"bob-device".to_vec()).unwrap();
        assert_eq!(conversation.member_count(), 2);
        let plaintext = b"hello over MLS";
        let (ciphertext_size, decrypted) = conversation.round_trip_from_alice(plaintext).unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(ciphertext_size > plaintext.len());
    }

    #[test]
    fn rejects_replayed_application_message() {
        let mut conversation =
            MlsConversation::new_1to1(b"alice-device".to_vec(), b"bob-device".to_vec()).unwrap();
        let ciphertext = conversation.encrypt_from_alice(b"one time").unwrap();
        assert_eq!(
            conversation.decrypt_for_bob(&ciphertext).unwrap(),
            b"one time"
        );
        assert!(conversation.decrypt_for_bob(&ciphertext).is_err());
    }
}
