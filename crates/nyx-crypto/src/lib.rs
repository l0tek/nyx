//! Cryptographic boundary.
//!
//! Production implementation must use OpenMLS for session/group E2EE.
//! Do not invent a custom ratchet or key-exchange protocol here.

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle, MlsGroup,
    MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn,
    ProcessedMessageContent, StagedWelcome,
    tls_codec::{Deserialize, Serialize},
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_traits::OpenMlsProvider;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use std::{
    collections::HashMap,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const NYX_CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
const MAX_DEVICE_IDENTITY_SIZE: usize = 1024;
const SNAPSHOT_VERSION: u16 = 3;
const MAX_INBOUND_RECEIPTS: usize = 4096;
const MAX_OUTBOUND_JOURNAL: usize = 1024;
const DEVICE_SNAPSHOT_VERSION: u16 = 1;
const INVITATION_VERSION: u16 = 1;
const MAX_DISPLAY_NAME_SIZE: usize = 64;
const MAX_CONTACTS: usize = 1024;
const INVITATION_LIFETIME_MS: i64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize, PartialEq, Eq)]
pub struct ContactRecord {
    pub invitation_id: Uuid,
    pub device_id: Uuid,
    pub display_name: String,
    pub identity_public_key: [u8; 32],
    pub identity_fingerprint: String,
    pub mls_key_package: Vec<u8>,
    pub mailbox_onion: String,
    /// Token used by this device when sending to the contact.
    pub send_mailbox_token: [u8; 32],
    /// Token polled by this device for messages sent by the contact.
    pub receive_mailbox_token: [u8; 32],
    pub verified: bool,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct IssuedInvitation {
    pub invitation_id: Uuid,
    pub inviter_receive_token: [u8; 32],
    pub invitee_receive_token: [u8; 32],
    pub expires_unix_ms: i64,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct ContactInvitationPayload {
    pub version: u16,
    pub invitation_id: Uuid,
    pub inviter_device_id: Uuid,
    pub inviter_display_name: String,
    pub inviter_identity_public_key: [u8; 32],
    pub mls_key_package: Vec<u8>,
    pub mailbox_onion: String,
    /// Recipient uses this token to send messages to the inviter.
    pub inviter_receive_token: [u8; 32],
    /// Recipient polls this token for messages sent by the inviter.
    pub invitee_receive_token: [u8; 32],
    pub created_unix_ms: i64,
    pub expires_unix_ms: i64,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct SignedContactInvitation {
    pub payload: ContactInvitationPayload,
    pub signature: Vec<u8>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct DeviceIdentitySnapshot {
    version: u16,
    device_id: Uuid,
    display_name: String,
    identity_secret_key: [u8; 32],
    identity_public_key: [u8; 32],
    mls_signature_key: Vec<u8>,
    mls_storage: HashMap<Vec<u8>, Vec<u8>>,
    mls_key_package: Vec<u8>,
    contacts: Vec<ContactRecord>,
    issued_invitations: Vec<IssuedInvitation>,
}

pub struct DeviceIdentity {
    snapshot: DeviceIdentitySnapshot,
}

impl Drop for DeviceIdentitySnapshot {
    fn drop(&mut self) {
        self.identity_secret_key.zeroize();
        self.mls_signature_key.zeroize();
        self.mls_key_package.zeroize();
        for (mut key, mut value) in self.mls_storage.drain() {
            key.zeroize();
            value.zeroize();
        }
        for contact in &mut self.contacts {
            contact.send_mailbox_token.zeroize();
            contact.receive_mailbox_token.zeroize();
            contact.mls_key_package.zeroize();
        }
        for invitation in &mut self.issued_invitations {
            invitation.inviter_receive_token.zeroize();
            invitation.invitee_receive_token.zeroize();
        }
    }
}

impl DeviceIdentity {
    pub fn generate(display_name: impl Into<String>) -> Result<Self> {
        let display_name = validate_display_name(display_name.into())?;
        let device_id = Uuid::new_v4();
        let mls_device = MlsDevice::generate(device_id.as_bytes().to_vec())?;
        let mls_key_package = mls_device
            .key_package()?
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| anyhow::anyhow!("serialize device MLS KeyPackage: {error:?}"))?;
        let mut identity_secret_key = [0_u8; 32];
        OsRng.fill_bytes(&mut identity_secret_key);
        let identity_public_key = SigningKey::from_bytes(&identity_secret_key)
            .verifying_key()
            .to_bytes();
        Ok(Self {
            snapshot: DeviceIdentitySnapshot {
                version: DEVICE_SNAPSHOT_VERSION,
                device_id,
                display_name,
                identity_secret_key,
                identity_public_key,
                mls_signature_key: mls_device.credential.signature_key.as_slice().to_vec(),
                mls_storage: clone_storage(mls_device.provider())?,
                mls_key_package,
                contacts: Vec::new(),
                issued_invitations: Vec::new(),
            },
        })
    }

    pub fn device_id(&self) -> Uuid {
        self.snapshot.device_id
    }

    pub fn display_name(&self) -> &str {
        &self.snapshot.display_name
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.snapshot.identity_public_key)
    }

    pub fn contacts(&self) -> &[ContactRecord] {
        &self.snapshot.contacts
    }

    pub fn create_invitation(&mut self, mailbox_onion: impl Into<String>) -> Result<String> {
        let mailbox_onion = validate_onion_address(mailbox_onion.into())?;
        let now = unix_time_ms()?;
        let mut inviter_receive_token = [0_u8; 32];
        let mut invitee_receive_token = [0_u8; 32];
        OsRng.fill_bytes(&mut inviter_receive_token);
        OsRng.fill_bytes(&mut invitee_receive_token);
        let payload = ContactInvitationPayload {
            version: INVITATION_VERSION,
            invitation_id: Uuid::new_v4(),
            inviter_device_id: self.snapshot.device_id,
            inviter_display_name: self.snapshot.display_name.clone(),
            inviter_identity_public_key: self.snapshot.identity_public_key,
            mls_key_package: self.snapshot.mls_key_package.clone(),
            mailbox_onion,
            inviter_receive_token,
            invitee_receive_token,
            created_unix_ms: now,
            expires_unix_ms: now.saturating_add(INVITATION_LIFETIME_MS),
        };
        let encoded_payload = postcard::to_allocvec(&payload).context("serialize invitation")?;
        let signature = SigningKey::from_bytes(&self.snapshot.identity_secret_key)
            .sign(&encoded_payload)
            .to_bytes()
            .to_vec();
        let invitation = SignedContactInvitation { payload, signature };
        self.snapshot.issued_invitations.push(IssuedInvitation {
            invitation_id: invitation.payload.invitation_id,
            inviter_receive_token: invitation.payload.inviter_receive_token,
            invitee_receive_token: invitation.payload.invitee_receive_token,
            expires_unix_ms: invitation.payload.expires_unix_ms,
        });
        Ok(URL_SAFE_NO_PAD
            .encode(postcard::to_allocvec(&invitation).context("serialize signed invitation")?))
    }

    pub fn issued_invitation(&self, invitation_id: Uuid) -> Option<&IssuedInvitation> {
        self.snapshot
            .issued_invitations
            .iter()
            .find(|invitation| invitation.invitation_id == invitation_id)
    }

    pub fn verify_invitation(encoded: &str) -> Result<ContactRecord> {
        if encoded.len() > 256 * 1024 {
            bail!("contact invitation exceeds maximum size");
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .context("decode contact invitation")?;
        let invitation: SignedContactInvitation =
            postcard::from_bytes(&bytes).context("deserialize contact invitation")?;
        let payload = &invitation.payload;
        if payload.version != INVITATION_VERSION {
            bail!("contact invitation version is unsupported");
        }
        validate_display_name(payload.inviter_display_name.clone())?;
        validate_onion_address(payload.mailbox_onion.clone())?;
        let now = unix_time_ms()?;
        if payload.created_unix_ms > now.saturating_add(5 * 60 * 1000)
            || payload.expires_unix_ms <= now
            || payload.expires_unix_ms <= payload.created_unix_ms
        {
            bail!("contact invitation is expired or has invalid timestamps");
        }
        let public_key = VerifyingKey::from_bytes(&payload.inviter_identity_public_key)
            .context("contact invitation identity key is invalid")?;
        let signature_bytes: [u8; 64] = invitation
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("contact invitation signature has invalid length"))?;
        let encoded_payload = postcard::to_allocvec(payload).context("serialize invitation")?;
        public_key
            .verify(&encoded_payload, &Signature::from_bytes(&signature_bytes))
            .context("contact invitation signature verification failed")?;
        let provider = OpenMlsRustCrypto::default();
        let key_package =
            openmls::prelude::KeyPackageIn::tls_deserialize_exact(payload.mls_key_package.clone())
                .map_err(|error| {
                    anyhow::anyhow!("deserialize invitation MLS KeyPackage: {error:?}")
                })?
                .validate(provider.crypto(), openmls::prelude::ProtocolVersion::Mls10)
                .map_err(|error| {
                    anyhow::anyhow!("validate invitation MLS KeyPackage: {error:?}")
                })?;
        if key_package.ciphersuite() != NYX_CIPHERSUITE {
            bail!("contact invitation uses an unsupported MLS ciphersuite");
        }
        Ok(ContactRecord {
            invitation_id: payload.invitation_id,
            device_id: payload.inviter_device_id,
            display_name: payload.inviter_display_name.clone(),
            identity_public_key: payload.inviter_identity_public_key,
            identity_fingerprint: fingerprint(&payload.inviter_identity_public_key),
            mls_key_package: payload.mls_key_package.clone(),
            mailbox_onion: payload.mailbox_onion.clone(),
            send_mailbox_token: payload.inviter_receive_token,
            receive_mailbox_token: payload.invitee_receive_token,
            verified: false,
        })
    }

    pub fn import_invitation(&mut self, encoded: &str) -> Result<ContactRecord> {
        if self.snapshot.contacts.len() >= MAX_CONTACTS {
            bail!("contact limit reached");
        }
        let contact = Self::verify_invitation(encoded)?;
        if contact.identity_public_key == self.snapshot.identity_public_key {
            bail!("cannot import an invitation from this device");
        }
        if self
            .snapshot
            .contacts
            .iter()
            .any(|existing| existing.device_id == contact.device_id)
        {
            bail!("contact device is already imported");
        }
        self.snapshot.contacts.push(contact.clone());
        Ok(contact)
    }

    pub fn mark_contact_verified(&mut self, device_id: Uuid) -> Result<()> {
        let contact = self
            .snapshot
            .contacts
            .iter_mut()
            .find(|contact| contact.device_id == device_id)
            .ok_or_else(|| anyhow::anyhow!("contact does not exist"))?;
        contact.verified = true;
        Ok(())
    }

    pub fn save_encrypted(&self, path: impl AsRef<Path>, password: &[u8]) -> Result<()> {
        let encoded = Zeroizing::new(
            postcard::to_allocvec(&self.snapshot).context("serialize device identity")?,
        );
        nyx_store::EncryptedBlobStore::save(path, password, &encoded)
            .context("save encrypted device identity")
    }

    pub fn load_encrypted(path: impl AsRef<Path>, password: &[u8]) -> Result<Self> {
        let encoded = nyx_store::EncryptedBlobStore::load(path, password)
            .context("load encrypted device identity")?;
        let snapshot: DeviceIdentitySnapshot =
            postcard::from_bytes(&encoded).context("deserialize device identity")?;
        if snapshot.version != DEVICE_SNAPSHOT_VERSION {
            bail!("device identity version is unsupported");
        }
        validate_display_name(snapshot.display_name.clone())?;
        let signing_key = SigningKey::from_bytes(&snapshot.identity_secret_key);
        if signing_key.verifying_key().to_bytes() != snapshot.identity_public_key {
            bail!("device identity key pair does not match");
        }
        let provider = provider_from_storage(snapshot.mls_storage.clone())?;
        read_signer(&provider, &snapshot.mls_signature_key)?;
        openmls::prelude::KeyPackageIn::tls_deserialize_exact(snapshot.mls_key_package.clone())
            .map_err(|error| anyhow::anyhow!("deserialize stored MLS KeyPackage: {error:?}"))?
            .validate(provider.crypto(), openmls::prelude::ProtocolVersion::Mls10)
            .map_err(|error| anyhow::anyhow!("validate stored MLS KeyPackage: {error:?}"))?;
        Ok(Self { snapshot })
    }
}

fn validate_display_name(display_name: String) -> Result<String> {
    let display_name = display_name.trim().to_owned();
    if display_name.is_empty() || display_name.len() > MAX_DISPLAY_NAME_SIZE {
        bail!("display name must contain between 1 and 64 bytes");
    }
    Ok(display_name)
}

fn validate_onion_address(address: String) -> Result<String> {
    let address = address.trim().to_ascii_lowercase();
    let service_id = address.strip_suffix(".onion").unwrap_or_default();
    if service_id.len() != 56
        || !service_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || matches!(byte, b'2'..=b'7'))
    {
        bail!("contact invitation requires a valid v3 Onion address");
    }
    Ok(address)
}

fn fingerprint(public_key: &[u8; 32]) -> String {
    let digest = blake3::hash(public_key);
    digest
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .chunks(4)
        .map(|chunk| chunk.concat())
        .collect::<Vec<_>>()
        .join(" ")
}

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
    pending_outbound: Vec<PendingOutbound>,
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
    pending_outbound: Vec<PendingOutbound>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct VersionTwoConversationSnapshot {
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

#[derive(Clone, SerdeSerialize, SerdeDeserialize)]
pub struct PendingOutbound {
    pub id: Uuid,
    pub mailbox_token: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl Drop for PendingOutbound {
    fn drop(&mut self) {
        self.mailbox_token.zeroize();
        self.ciphertext.zeroize();
    }
}

impl Drop for MlsConversation {
    fn drop(&mut self) {
        self.inbound_receipts.zeroize();
        self.pending_outbound.clear();
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

impl Drop for VersionTwoConversationSnapshot {
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
        self.pending_outbound.clear();
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
            pending_outbound: Vec::new(),
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

    /// Creates an outbound MLS message and persists the advanced sender and
    /// demo-peer ratchets together with a durable handoff record. A failed save
    /// restores the complete pre-message state.
    pub fn create_outbound_and_save(
        &mut self,
        plaintext: &[u8],
        mailbox_token: [u8; 32],
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<(PendingOutbound, Vec<u8>)> {
        if self.pending_outbound.len() >= MAX_OUTBOUND_JOURNAL {
            bail!("outbound MLS journal is full");
        }
        let before = self.snapshot()?;
        let ciphertext = self.encrypt_from_alice(plaintext)?;
        let decrypted = match self.decrypt_for_bob(&ciphertext) {
            Ok(decrypted) => decrypted,
            Err(error) => {
                *self = Self::from_snapshot(before)?;
                return Err(error);
            }
        };
        let pending = PendingOutbound {
            id: Uuid::new_v4(),
            mailbox_token,
            ciphertext,
        };
        let mut snapshot = self.snapshot()?;
        snapshot.pending_outbound.push(pending.clone());
        if let Err(error) = Self::save_snapshot(&snapshot, path, password) {
            *self = Self::from_snapshot(before)
                .context("restore MLS state after failed outbound safe-save")?;
            return Err(error);
        }
        *self = Self::from_snapshot(snapshot)?;
        Ok((pending, decrypted))
    }

    pub fn pending_outbound(&self) -> Vec<PendingOutbound> {
        self.pending_outbound.clone()
    }

    /// Removes a handoff record only after SQLite accepted the same stable ID.
    pub fn mark_outbound_queued_and_save(
        &mut self,
        id: Uuid,
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<()> {
        if !self.pending_outbound.iter().any(|pending| pending.id == id) {
            bail!("outbound MLS journal entry does not exist");
        }
        let mut snapshot = self.snapshot()?;
        snapshot.pending_outbound.retain(|pending| pending.id != id);
        Self::save_snapshot(&snapshot, path, password)?;
        *self = Self::from_snapshot(snapshot)?;
        Ok(())
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
            pending_outbound: self.pending_outbound(),
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
                if let Ok(mut version_two) =
                    postcard::from_bytes::<VersionTwoConversationSnapshot>(&encoded)
                    && version_two.version == 2
                {
                    ConversationSnapshot {
                        version: SNAPSHOT_VERSION,
                        group_id: std::mem::take(&mut version_two.group_id),
                        alice_signature_key: std::mem::take(&mut version_two.alice_signature_key),
                        bob_signature_key: std::mem::take(&mut version_two.bob_signature_key),
                        alice_storage: std::mem::take(&mut version_two.alice_storage),
                        bob_storage: std::mem::take(&mut version_two.bob_storage),
                        inbound_receipts: std::mem::take(&mut version_two.inbound_receipts),
                        pending_outbound: Vec::new(),
                    }
                } else {
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
                        pending_outbound: Vec::new(),
                    }
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
            pending_outbound: std::mem::take(&mut snapshot.pending_outbound),
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

    #[test]
    fn loads_version_two_snapshot_without_outbound_journal() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("version-two.nyx");
        let conversation = MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();
        let version_two = VersionTwoConversationSnapshot {
            version: 2,
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
            inbound_receipts: Vec::new(),
        };
        let encoded = zeroize::Zeroizing::new(postcard::to_allocvec(&version_two).unwrap());
        nyx_store::EncryptedBlobStore::save(&path, b"vault password", &encoded).unwrap();

        let restored = MlsConversation::load_encrypted(&path, b"vault password").unwrap();
        assert_eq!(restored.member_count(), 2);
        assert!(restored.pending_outbound().is_empty());
    }

    #[test]
    fn outbound_ratchets_and_queue_handoff_are_saved_together() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.nyx");
        let mut conversation =
            MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();

        let (pending, decrypted) = conversation
            .create_outbound_and_save(b"durable outbound", [8; 32], &path, b"vault password")
            .unwrap();
        assert_eq!(decrypted, b"durable outbound");
        assert_eq!(conversation.pending_outbound().len(), 1);

        let mut restored = MlsConversation::load_encrypted(&path, b"vault password").unwrap();
        assert_eq!(restored.pending_outbound()[0].id, pending.id);
        restored
            .mark_outbound_queued_and_save(pending.id, &path, b"vault password")
            .unwrap();
        assert!(
            MlsConversation::load_encrypted(&path, b"vault password")
                .unwrap()
                .pending_outbound()
                .is_empty()
        );
    }

    #[test]
    fn failed_outbound_safe_save_restores_ratchets() {
        let directory = tempfile::tempdir().unwrap();
        let valid_path = directory.path().join("state.nyx");
        let mut conversation =
            MlsConversation::new_1to1(b"alice".to_vec(), b"bob".to_vec()).unwrap();

        assert!(
            conversation
                .create_outbound_and_save(
                    b"retry outbound",
                    [5; 32],
                    directory.path(),
                    b"vault password",
                )
                .is_err()
        );
        assert!(conversation.pending_outbound().is_empty());
        let (_, decrypted) = conversation
            .create_outbound_and_save(b"retry outbound", [5; 32], valid_path, b"vault password")
            .unwrap();
        assert_eq!(decrypted, b"retry outbound");
    }

    #[test]
    fn persistent_device_identity_round_trips() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("identity.nyx");
        let identity = DeviceIdentity::generate("Alice").unwrap();
        let device_id = identity.device_id();
        let fingerprint = identity.fingerprint();
        identity
            .save_encrypted(&path, b"strong local password")
            .unwrap();

        let restored = DeviceIdentity::load_encrypted(&path, b"strong local password").unwrap();
        assert_eq!(restored.device_id(), device_id);
        assert_eq!(restored.display_name(), "Alice");
        assert_eq!(restored.fingerprint(), fingerprint);
        assert!(DeviceIdentity::load_encrypted(&path, b"wrong password").is_err());
    }

    #[test]
    fn signed_contact_invitation_verifies_key_package_and_directions() {
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let invitation = alice
            .create_invitation("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion")
            .unwrap();
        let encoded = URL_SAFE_NO_PAD.decode(&invitation).unwrap();
        let signed: SignedContactInvitation = postcard::from_bytes(&encoded).unwrap();
        let contact = DeviceIdentity::verify_invitation(&invitation).unwrap();
        assert_eq!(contact.device_id, alice.device_id());
        assert_eq!(contact.display_name, "Alice");
        assert_eq!(
            contact.send_mailbox_token,
            signed.payload.inviter_receive_token
        );
        assert_eq!(
            contact.receive_mailbox_token,
            signed.payload.invitee_receive_token
        );
        assert!(!contact.verified);
    }

    #[test]
    fn modified_contact_invitation_is_rejected() {
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let invitation = alice
            .create_invitation("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion")
            .unwrap();
        let encoded = URL_SAFE_NO_PAD.decode(&invitation).unwrap();
        let mut signed: SignedContactInvitation = postcard::from_bytes(&encoded).unwrap();
        signed.payload.inviter_display_name = "Mallory".into();
        let tampered = URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&signed).unwrap());
        assert!(DeviceIdentity::verify_invitation(&tampered).is_err());
    }

    #[test]
    fn imported_contact_and_verification_are_persistent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("bob-identity.nyx");
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let invitation = alice
            .create_invitation("25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion")
            .unwrap();
        let mut bob = DeviceIdentity::generate("Bob").unwrap();
        let contact = bob.import_invitation(&invitation).unwrap();
        assert!(bob.import_invitation(&invitation).is_err());
        bob.mark_contact_verified(contact.device_id).unwrap();
        bob.save_encrypted(&path, b"strong local password").unwrap();

        let restored = DeviceIdentity::load_encrypted(&path, b"strong local password").unwrap();
        assert_eq!(restored.contacts().len(), 1);
        assert!(restored.contacts()[0].verified);
        assert_eq!(restored.contacts()[0].device_id, alice.device_id());
    }
}
