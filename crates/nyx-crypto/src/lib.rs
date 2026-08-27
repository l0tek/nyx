//! Cryptographic boundary.
//!
//! Production implementation must use OpenMLS for session/group E2EE.
//! Do not invent a custom ratchet or key-exchange protocol here.

use anyhow::{Context, Result, bail};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, StagedWelcome, tls_codec::Deserialize,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{
    collections::HashMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const NYX_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_DEVICE_IDENTITY_SIZE: usize = 1024;
const SNAPSHOT_VERSION: u16 = 2;
const MAX_INBOUND_RECEIPTS: usize = 4096;

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
    key_package: Option<KeyPackageBundle>,
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
    inbound_receipts: Vec<InboundReceipt>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct ConversationSnapshot {
    version: u16,
    group_id: Vec<u8>,
    alice_signature_key: Vec<u8>,
    bob_signature_key: Vec<u8>,
    alice_storage: HashMap<Vec<u8>, Vec<u8>>,
    bob_storage: HashMap<Vec<u8>, Vec<u8>>,
    inbound_receipts: Vec<InboundReceipt>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct LegacyConversationSnapshot {
    version: u16,
    group_id: Vec<u8>,
    alice_signature_key: Vec<u8>,
    bob_signature_key: Vec<u8>,
    alice_storage: HashMap<Vec<u8>, Vec<u8>>,
    bob_storage: HashMap<Vec<u8>, Vec<u8>>,
}

#[derive(Clone, SerdeSerialize, SerdeDeserialize, Zeroize)]
struct InboundReceipt {
    receipt: [u8; 32],
    expires_unix_ms: i64,
}

impl Drop for MlsConversation {
    fn drop(&mut self) {
        self.inbound_receipts.zeroize();
    }
}

impl Drop for LegacyConversationSnapshot {
    fn drop(&mut self) {
        self.group_id.zeroize();
        self.alice_signature_key.zeroize();
        self.bob_signature_key.zeroize();
        for (mut key, mut value) in self.alice_storage.drain() {
            key.zeroize();
            value.zeroize();
        }
        for (mut key, mut value) in self.bob_storage.drain() {
            key.zeroize();
            value.zeroize();
        }
    }
}

impl Drop for ConversationSnapshot {
    fn drop(&mut self) {
        self.group_id.zeroize();
        self.alice_signature_key.zeroize();
        self.bob_signature_key.zeroize();
        for (mut key, mut value) in self.alice_storage.drain() {
            key.zeroize();
            value.zeroize();
        }
        for (mut key, mut value) in self.bob_storage.drain() {
            key.zeroize();
            value.zeroize();
        }
        self.inbound_receipts.zeroize();
    }
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
            key_package: Some(key_package),
        })
    }

    pub fn credential(&self) -> &CredentialWithKey {
        &self.credential
    }

    pub fn key_package(&self) -> Result<&KeyPackageBundle> {
        self.key_package
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("restored MLS device has no unused KeyPackage"))
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
                &[bob.key_package()?.key_package().clone()],
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
            inbound_receipts: Vec::new(),
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

    pub fn encrypt_from_bob(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("MLS application message must not be empty");
        }
        self.bob_group
            .create_message(self.bob.provider(), self.bob.signer(), plaintext)
            .map_err(|error| anyhow::anyhow!("encrypt peer MLS application message: {error:?}"))?
            .to_bytes()
            .map_err(|error| anyhow::anyhow!("serialize peer MLS application message: {error:?}"))
    }

    pub fn decrypt_for_alice(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| anyhow::anyhow!("deserialize peer MLS message: {error:?}"))?;
        let protocol_message = message
            .try_into_protocol_message()
            .map_err(|error| anyhow::anyhow!("expected a peer MLS protocol message: {error:?}"))?;
        let processed = self
            .alice_group
            .process_message(self.alice.provider(), protocol_message)
            .map_err(|error| anyhow::anyhow!("decrypt peer MLS application message: {error:?}"))?;
        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => Ok(message.into_bytes()),
            _ => bail!("received peer MLS message is not application data"),
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

    pub fn has_inbound_receipt(&self, receipt: &[u8; 32]) -> bool {
        self.inbound_receipts()
            .iter()
            .any(|entry| &entry.receipt == receipt)
    }

    /// Advances the local MLS ratchet, journals the mailbox receipt, and
    /// atomically persists both in one encrypted snapshot. If persistence
    /// fails, the pre-message ratchet state is restored before returning.
    pub fn process_inbound_and_save(
        &mut self,
        ciphertext: &[u8],
        receipt: [u8; 32],
        expires_unix_ms: i64,
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<Vec<u8>> {
        if self.has_inbound_receipt(&receipt) {
            bail!("inbound mailbox receipt was already processed");
        }
        let before = self.snapshot()?;
        let plaintext = self.decrypt_for_alice(ciphertext)?;
        let now = unix_time_ms()?;
        let mut snapshot = self.snapshot()?;
        snapshot
            .inbound_receipts
            .retain(|entry| entry.expires_unix_ms > now);
        if snapshot.inbound_receipts.len() >= MAX_INBOUND_RECEIPTS {
            *self = Self::from_snapshot(before)?;
            bail!("inbound receipt journal is full");
        }
        snapshot.inbound_receipts.push(InboundReceipt {
            receipt,
            expires_unix_ms,
        });
        if let Err(error) = Self::save_snapshot(&snapshot, path, password) {
            *self = Self::from_snapshot(before)
                .context("restore MLS state after failed inbound safe-save")?;
            return Err(error);
        }
        // Reloading the just-persisted snapshot also installs the pruned and
        // newly journaled receipt set in the live conversation.
        *self = Self::from_snapshot(snapshot)?;
        Ok(plaintext)
    }

    pub fn save_encrypted(&self, path: impl AsRef<Path>, password: &[u8]) -> Result<()> {
        let snapshot = self.snapshot()?;
        Self::save_snapshot(&snapshot, path, password)
    }

    fn snapshot(&self) -> Result<ConversationSnapshot> {
        Ok(ConversationSnapshot {
            version: SNAPSHOT_VERSION,
            group_id: self.alice_group.group_id().as_slice().to_vec(),
            alice_signature_key: self.alice.credential.signature_key.as_slice().to_vec(),
            bob_signature_key: self.bob.credential.signature_key.as_slice().to_vec(),
            alice_storage: clone_storage(self.alice.provider())?,
            bob_storage: clone_storage(self.bob.provider())?,
            inbound_receipts: self.inbound_receipts().to_vec(),
        })
    }

    fn save_snapshot(
        snapshot: &ConversationSnapshot,
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<()> {
        let encoded = zeroize::Zeroizing::new(
            postcard::to_allocvec(snapshot).context("serialize MLS snapshot")?,
        );
        nyx_store::EncryptedBlobStore::save(path, password, &encoded)
            .context("save encrypted MLS snapshot")
    }

    pub fn load_encrypted(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let encoded = nyx_store::EncryptedBlobStore::load(path, password)
            .context("load encrypted MLS snapshot")?;
        let snapshot = match postcard::from_bytes::<ConversationSnapshot>(&encoded) {
            Ok(snapshot) if snapshot.version == SNAPSHOT_VERSION => snapshot,
            _ => {
                let mut legacy: LegacyConversationSnapshot =
                    postcard::from_bytes(&encoded).context("deserialize MLS snapshot")?;
                if legacy.version != 1 {
                    bail!("MLS snapshot version is unsupported");
                }
                ConversationSnapshot {
                    version: SNAPSHOT_VERSION,
                    group_id: std::mem::take(&mut legacy.group_id),
                    alice_signature_key: std::mem::take(&mut legacy.alice_signature_key),
                    bob_signature_key: std::mem::take(&mut legacy.bob_signature_key),
                    alice_storage: std::mem::take(&mut legacy.alice_storage),
                    bob_storage: std::mem::take(&mut legacy.bob_storage),
                    inbound_receipts: Vec::new(),
                }
            }
        };
        Self::from_snapshot(snapshot)
    }

    fn from_snapshot(mut snapshot: ConversationSnapshot) -> Result<Self> {
        let alice_provider = provider_from_storage(std::mem::take(&mut snapshot.alice_storage))?;
        let bob_provider = provider_from_storage(std::mem::take(&mut snapshot.bob_storage))?;
        let group_id = openmls::prelude::GroupId::from_slice(&snapshot.group_id);
        let alice_group = MlsGroup::load(alice_provider.storage(), &group_id)
            .map_err(|error| anyhow::anyhow!("load local MLS group: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("local MLS group is absent from snapshot"))?;
        let bob_group = MlsGroup::load(bob_provider.storage(), &group_id)
            .map_err(|error| anyhow::anyhow!("load peer MLS group: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("peer MLS group is absent from snapshot"))?;
        let alice_signer = read_signer(&alice_provider, &snapshot.alice_signature_key)?;
        let bob_signer = read_signer(&bob_provider, &snapshot.bob_signature_key)?;
        let alice_credential = CredentialWithKey {
            credential: alice_group
                .credential()
                .map_err(|error| anyhow::anyhow!("read local MLS credential: {error:?}"))?
                .clone(),
            signature_key: std::mem::take(&mut snapshot.alice_signature_key).into(),
        };
        let bob_credential = CredentialWithKey {
            credential: bob_group
                .credential()
                .map_err(|error| anyhow::anyhow!("read peer MLS credential: {error:?}"))?
                .clone(),
            signature_key: std::mem::take(&mut snapshot.bob_signature_key).into(),
        };
        if alice_group.epoch_authenticator().as_slice()
            != bob_group.epoch_authenticator().as_slice()
        {
            bail!("restored MLS members have different epoch authenticators");
        }
        Ok(Self {
            alice: MlsDevice {
                provider: alice_provider,
                signer: alice_signer,
                credential: alice_credential,
                key_package: None,
            },
            bob: MlsDevice {
                provider: bob_provider,
                signer: bob_signer,
                credential: bob_credential,
                key_package: None,
            },
            alice_group,
            bob_group,
            inbound_receipts: std::mem::take(&mut snapshot.inbound_receipts),
        })
    }

    fn inbound_receipts(&self) -> &[InboundReceipt] {
        &self.inbound_receipts
    }
}

fn clone_storage(provider: &OpenMlsRustCrypto) -> Result<HashMap<Vec<u8>, Vec<u8>>> {
    provider
        .storage()
        .values
        .read()
        .map(|values| values.clone())
        .map_err(|_| anyhow::anyhow!("OpenMLS storage lock poisoned"))
}

fn provider_from_storage(values: HashMap<Vec<u8>, Vec<u8>>) -> Result<OpenMlsRustCrypto> {
    let provider = OpenMlsRustCrypto::default();
    *provider
        .storage()
        .values
        .write()
        .map_err(|_| anyhow::anyhow!("OpenMLS storage lock poisoned"))? = values;
    Ok(provider)
}

fn read_signer(provider: &OpenMlsRustCrypto, public_key: &[u8]) -> Result<SignatureKeyPair> {
    SignatureKeyPair::read(
        provider.storage(),
        public_key,
        NYX_CIPHERSUITE.signature_algorithm(),
    )
    .ok_or_else(|| anyhow::anyhow!("MLS signature key is absent from snapshot"))
}

fn unix_time_ms() -> Result<i64> {
    let value = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    i64::try_from(value).context("system time exceeds receipt timestamp range")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_device_credential_and_key_package() {
        let device = MlsDevice::generate(b"device-1".to_vec()).unwrap();
        assert_eq!(
            device.key_package().unwrap().key_package().ciphersuite(),
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

    #[test]
    fn exchanges_application_message_from_peer_to_local_device() {
        let mut conversation =
            MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();
        let ciphertext = conversation.encrypt_from_bob(b"reply from peer").unwrap();
        assert_eq!(
            conversation.decrypt_for_alice(&ciphertext).unwrap(),
            b"reply from peer"
        );
        assert!(conversation.decrypt_for_alice(&ciphertext).is_err());
    }

    #[test]
    fn encrypted_snapshot_restores_message_ratchets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("conversation.nyx");
        let mut conversation =
            MlsConversation::new_1to1(b"alice-device".to_vec(), b"bob-device".to_vec()).unwrap();
        assert_eq!(
            conversation
                .round_trip_from_alice(b"before save")
                .unwrap()
                .1,
            b"before save"
        );
        conversation
            .save_encrypted(&path, b"strong test password")
            .unwrap();
        drop(conversation);

        let mut restored = MlsConversation::load_encrypted(&path, b"strong test password").unwrap();
        assert_eq!(restored.member_count(), 2);
        assert_eq!(
            restored.round_trip_from_alice(b"after restore").unwrap().1,
            b"after restore"
        );
        assert!(MlsConversation::load_encrypted(&path, b"wrong password").is_err());
    }

    #[test]
    fn inbound_receipt_and_ratchet_are_saved_together() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.nyx");
        let mut conversation =
            MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();
        let ciphertext = conversation.encrypt_from_bob(b"durable inbound").unwrap();
        let receipt = [42; 32];

        let plaintext = conversation
            .process_inbound_and_save(&ciphertext, receipt, i64::MAX, &path, b"vault password")
            .unwrap();
        assert_eq!(plaintext, b"durable inbound");
        assert!(conversation.has_inbound_receipt(&receipt));

        let restored = MlsConversation::load_encrypted(&path, b"vault password").unwrap();
        assert!(restored.has_inbound_receipt(&receipt));
    }

    #[test]
    fn failed_inbound_safe_save_restores_ratchet() {
        let directory = tempfile::tempdir().unwrap();
        let valid_path = directory.path().join("state.nyx");
        let invalid_path = directory.path();
        let mut conversation =
            MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();
        let ciphertext = conversation
            .encrypt_from_bob(b"retry after failure")
            .unwrap();

        assert!(
            conversation
                .process_inbound_and_save(
                    &ciphertext,
                    [7; 32],
                    i64::MAX,
                    invalid_path,
                    b"vault password",
                )
                .is_err()
        );
        assert!(!conversation.has_inbound_receipt(&[7; 32]));
        assert_eq!(
            conversation
                .process_inbound_and_save(
                    &ciphertext,
                    [7; 32],
                    i64::MAX,
                    valid_path,
                    b"vault password",
                )
                .unwrap(),
            b"retry after failure"
        );
    }

    #[test]
    fn loads_version_one_snapshot_without_receipt_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.nyx");
        let conversation = MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();
        let legacy = LegacyConversationSnapshot {
            version: 1,
            group_id: conversation.alice_group.group_id().as_slice().to_vec(),
            alice_signature_key: conversation
                .alice
                .credential
                .signature_key
                .as_slice()
                .to_vec(),
            bob_signature_key: conversation
                .bob
                .credential
                .signature_key
                .as_slice()
                .to_vec(),
            alice_storage: clone_storage(conversation.alice.provider()).unwrap(),
            bob_storage: clone_storage(conversation.bob.provider()).unwrap(),
        };
        let encoded = zeroize::Zeroizing::new(postcard::to_allocvec(&legacy).unwrap());
        nyx_store::EncryptedBlobStore::save(&path, b"vault password", &encoded).unwrap();

        let restored = MlsConversation::load_encrypted(&path, b"vault password").unwrap();
        assert_eq!(restored.member_count(), 2);
        assert!(!restored.has_inbound_receipt(&[1; 32]));
    }
}
