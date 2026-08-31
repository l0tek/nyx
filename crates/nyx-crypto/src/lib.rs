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
const INVITATION_VERSION: u16 = 3;
const MAX_TRANSPORT_EXTENSION_SIZE: usize = 4096;
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
    /// Meshtastic destination bound locally to this verified contact.
    pub meshtastic_node_id: Option<u32>,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
struct PreviousContactRecord {
    invitation_id: Uuid,
    device_id: Uuid,
    display_name: String,
    identity_public_key: [u8; 32],
    identity_fingerprint: String,
    mls_key_package: Vec<u8>,
    mailbox_onion: String,
    send_mailbox_token: [u8; 32],
    receive_mailbox_token: [u8; 32],
    verified: bool,
}

impl From<PreviousContactRecord> for ContactRecord {
    fn from(contact: PreviousContactRecord) -> Self {
        Self {
            invitation_id: contact.invitation_id,
            device_id: contact.device_id,
            display_name: contact.display_name,
            identity_public_key: contact.identity_public_key,
            identity_fingerprint: contact.identity_fingerprint,
            mls_key_package: contact.mls_key_package,
            mailbox_onion: contact.mailbox_onion,
            send_mailbox_token: contact.send_mailbox_token,
            receive_mailbox_token: contact.receive_mailbox_token,
            verified: contact.verified,
            meshtastic_node_id: None,
        }
    }
}

#[cfg(test)]
impl From<ContactRecord> for PreviousContactRecord {
    fn from(contact: ContactRecord) -> Self {
        Self {
            invitation_id: contact.invitation_id,
            device_id: contact.device_id,
            display_name: contact.display_name,
            identity_public_key: contact.identity_public_key,
            identity_fingerprint: contact.identity_fingerprint,
            mls_key_package: contact.mls_key_package,
            mailbox_onion: contact.mailbox_onion,
            send_mailbox_token: contact.send_mailbox_token,
            receive_mailbox_token: contact.receive_mailbox_token,
            verified: contact.verified,
        }
    }
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct IssuedInvitation {
    pub invitation_id: Uuid,
    pub inviter_receive_token: [u8; 32],
    pub invitee_receive_token: [u8; 32],
    pub expires_unix_ms: i64,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize, PartialEq, Eq)]
pub struct RemoteSession {
    pub invitation_id: Uuid,
    pub contact_device_id: Uuid,
    pub group_id: Vec<u8>,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct InvitationAcceptancePayload {
    pub version: u16,
    pub invitation_id: Uuid,
    pub accepter_device_id: Uuid,
    pub accepter_display_name: String,
    pub accepter_identity_public_key: [u8; 32],
    pub accepter_mls_key_package: Vec<u8>,
    pub mailbox_onion: String,
    pub meshtastic_node_id: Option<u32>,
    pub welcome: Vec<u8>,
}

#[derive(Clone, Debug, SerdeSerialize, SerdeDeserialize)]
pub struct SignedInvitationAcceptance {
    pub payload: InvitationAcceptancePayload,
    pub signature: Vec<u8>,
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
    pub meshtastic_node_id: Option<u32>,
    /// Opaque, signed transport bootstrap data interpreted outside this crate.
    pub transport_extension: Vec<u8>,
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
    #[serde(default)]
    sessions: Vec<RemoteSession>,
    #[serde(default)]
    remote_inbound_receipts: Vec<InboundReceipt>,
    #[serde(default)]
    remote_pending_outbound: Vec<PendingOutbound>,
    mailbox_onion: Option<String>,
    mailboxes: Vec<String>,
}

#[derive(SerdeDeserialize)]
struct PreviousDeviceIdentitySnapshot {
    version: u16,
    device_id: Uuid,
    display_name: String,
    identity_secret_key: [u8; 32],
    identity_public_key: [u8; 32],
    mls_signature_key: Vec<u8>,
    mls_storage: HashMap<Vec<u8>, Vec<u8>>,
    mls_key_package: Vec<u8>,
    contacts: Vec<PreviousContactRecord>,
    issued_invitations: Vec<IssuedInvitation>,
    sessions: Vec<RemoteSession>,
    remote_inbound_receipts: Vec<InboundReceipt>,
    remote_pending_outbound: Vec<PendingOutbound>,
    mailbox_onion: Option<String>,
}

impl From<PreviousDeviceIdentitySnapshot> for DeviceIdentitySnapshot {
    fn from(previous: PreviousDeviceIdentitySnapshot) -> Self {
        let mailboxes = previous.mailbox_onion.iter().cloned().collect();
        Self {
            version: previous.version,
            device_id: previous.device_id,
            display_name: previous.display_name,
            identity_secret_key: previous.identity_secret_key,
            identity_public_key: previous.identity_public_key,
            mls_signature_key: previous.mls_signature_key,
            mls_storage: previous.mls_storage,
            mls_key_package: previous.mls_key_package,
            contacts: previous.contacts.into_iter().map(Into::into).collect(),
            issued_invitations: previous.issued_invitations,
            sessions: previous.sessions,
            remote_inbound_receipts: previous.remote_inbound_receipts,
            remote_pending_outbound: previous.remote_pending_outbound,
            mailbox_onion: previous.mailbox_onion,
            mailboxes,
        }
    }
}

// Snapshot layout used before remote MLS sessions were added. Postcard encodes
// structs positionally and cannot apply serde defaults when an older payload
// ends before newly appended fields, so this layout is required for migration.
#[derive(SerdeSerialize, SerdeDeserialize)]
struct LegacyDeviceIdentitySnapshot {
    version: u16,
    device_id: Uuid,
    display_name: String,
    identity_secret_key: [u8; 32],
    identity_public_key: [u8; 32],
    mls_signature_key: Vec<u8>,
    mls_storage: HashMap<Vec<u8>, Vec<u8>>,
    mls_key_package: Vec<u8>,
    contacts: Vec<PreviousContactRecord>,
    issued_invitations: Vec<IssuedInvitation>,
    #[serde(default)]
    sessions: Vec<RemoteSession>,
    #[serde(default)]
    remote_inbound_receipts: Vec<InboundReceipt>,
    #[serde(default)]
    remote_pending_outbound: Vec<PendingOutbound>,
}

#[derive(SerdeSerialize, SerdeDeserialize)]
struct OriginalDeviceIdentitySnapshot {
    version: u16,
    device_id: Uuid,
    display_name: String,
    identity_secret_key: [u8; 32],
    identity_public_key: [u8; 32],
    mls_signature_key: Vec<u8>,
    mls_storage: HashMap<Vec<u8>, Vec<u8>>,
    mls_key_package: Vec<u8>,
    contacts: Vec<PreviousContactRecord>,
    issued_invitations: Vec<IssuedInvitation>,
}

impl From<LegacyDeviceIdentitySnapshot> for DeviceIdentitySnapshot {
    fn from(legacy: LegacyDeviceIdentitySnapshot) -> Self {
        Self {
            version: legacy.version,
            device_id: legacy.device_id,
            display_name: legacy.display_name,
            identity_secret_key: legacy.identity_secret_key,
            identity_public_key: legacy.identity_public_key,
            mls_signature_key: legacy.mls_signature_key,
            mls_storage: legacy.mls_storage,
            mls_key_package: legacy.mls_key_package,
            contacts: legacy.contacts.into_iter().map(Into::into).collect(),
            issued_invitations: legacy.issued_invitations,
            sessions: legacy.sessions,
            remote_inbound_receipts: legacy.remote_inbound_receipts,
            remote_pending_outbound: legacy.remote_pending_outbound,
            mailbox_onion: None,
            mailboxes: Vec::new(),
        }
    }
}

impl From<OriginalDeviceIdentitySnapshot> for DeviceIdentitySnapshot {
    fn from(original: OriginalDeviceIdentitySnapshot) -> Self {
        LegacyDeviceIdentitySnapshot {
            version: original.version,
            device_id: original.device_id,
            display_name: original.display_name,
            identity_secret_key: original.identity_secret_key,
            identity_public_key: original.identity_public_key,
            mls_signature_key: original.mls_signature_key,
            mls_storage: original.mls_storage,
            mls_key_package: original.mls_key_package,
            contacts: original.contacts,
            issued_invitations: original.issued_invitations,
            sessions: Vec::new(),
            remote_inbound_receipts: Vec::new(),
            remote_pending_outbound: Vec::new(),
        }
        .into()
    }
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
        self.remote_inbound_receipts.zeroize();
        self.remote_pending_outbound.clear();
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
                sessions: Vec::new(),
                remote_inbound_receipts: Vec::new(),
                remote_pending_outbound: Vec::new(),
                mailbox_onion: None,
                mailboxes: Vec::new(),
            },
        })
    }

    pub fn device_id(&self) -> Uuid {
        self.snapshot.device_id
    }

    pub fn display_name(&self) -> &str {
        &self.snapshot.display_name
    }

    pub fn mailbox_onion(&self) -> Option<&str> {
        self.snapshot.mailbox_onion.as_deref()
    }

    pub fn mailboxes(&self) -> &[String] {
        &self.snapshot.mailboxes
    }

    pub fn add_mailbox(&mut self, mailbox_onion: impl Into<String>) -> Result<()> {
        let mailbox_onion = validate_onion_address(mailbox_onion.into())?;
        if !self.snapshot.mailboxes.contains(&mailbox_onion) {
            self.snapshot.mailboxes.push(mailbox_onion.clone());
        }
        self.snapshot.mailbox_onion = Some(mailbox_onion);
        Ok(())
    }

    pub fn update_mailbox(&mut self, index: usize, mailbox_onion: impl Into<String>) -> Result<()> {
        let mailbox_onion = validate_onion_address(mailbox_onion.into())?;
        let previous = self
            .snapshot
            .mailboxes
            .get_mut(index)
            .ok_or_else(|| anyhow::anyhow!("mailbox does not exist"))?;
        let was_active = self.snapshot.mailbox_onion.as_ref() == Some(previous);
        *previous = mailbox_onion.clone();
        if was_active {
            self.snapshot.mailbox_onion = Some(mailbox_onion);
        }
        Ok(())
    }

    pub fn select_mailbox(&mut self, index: usize) -> Result<()> {
        self.snapshot.mailbox_onion = Some(
            self.snapshot
                .mailboxes
                .get(index)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("mailbox does not exist"))?,
        );
        Ok(())
    }

    pub fn remove_mailbox(&mut self, index: usize) -> Result<()> {
        if index >= self.snapshot.mailboxes.len() {
            bail!("mailbox does not exist");
        }
        if self.snapshot.mailboxes.len() == 1 {
            bail!("the last mailbox cannot be removed");
        }
        let removed = self.snapshot.mailboxes.remove(index);
        if self.snapshot.mailbox_onion.as_deref() == Some(&removed) {
            self.snapshot.mailbox_onion = self.snapshot.mailboxes.first().cloned();
        }
        Ok(())
    }

    pub fn remove_mailbox_address(&mut self, address: &str) -> Result<()> {
        let index = self
            .snapshot
            .mailboxes
            .iter()
            .position(|candidate| candidate == address)
            .ok_or_else(|| anyhow::anyhow!("mailbox does not exist"))?;
        self.remove_mailbox(index)
    }

    pub fn update_profile(
        &mut self,
        display_name: impl Into<String>,
        mailbox_onion: impl Into<String>,
    ) -> Result<()> {
        let display_name = validate_display_name(display_name.into())?;
        let mailbox_onion = validate_onion_address(mailbox_onion.into())?;
        self.snapshot.display_name = display_name;
        self.snapshot.mailbox_onion = Some(mailbox_onion);
        if !self
            .snapshot
            .mailboxes
            .contains(self.snapshot.mailbox_onion.as_ref().unwrap())
        {
            self.snapshot
                .mailboxes
                .push(self.snapshot.mailbox_onion.clone().unwrap());
        }
        Ok(())
    }

    pub fn fingerprint(&self) -> String {
        fingerprint(&self.snapshot.identity_public_key)
    }

    pub fn contacts(&self) -> &[ContactRecord] {
        &self.snapshot.contacts
    }

    pub fn sessions(&self) -> &[RemoteSession] {
        &self.snapshot.sessions
    }

    pub fn has_session(&self, device_id: Uuid) -> bool {
        self.snapshot
            .sessions
            .iter()
            .any(|session| session.contact_device_id == device_id)
    }

    pub fn has_remote_inbound_receipt(&self, receipt: &[u8; 32]) -> bool {
        self.snapshot
            .remote_inbound_receipts
            .iter()
            .any(|entry| &entry.receipt == receipt)
    }

    pub fn remote_pending_outbound(&self) -> Vec<PendingOutbound> {
        self.snapshot.remote_pending_outbound.clone()
    }

    pub fn create_invitation(&mut self, mailbox_onion: impl Into<String>) -> Result<String> {
        self.create_invitation_with_meshtastic_node(mailbox_onion, None)
    }

    pub fn create_invitation_with_meshtastic_node(
        &mut self,
        mailbox_onion: impl Into<String>,
        meshtastic_node_id: Option<u32>,
    ) -> Result<String> {
        self.create_invitation_with_transport_extension(
            mailbox_onion,
            meshtastic_node_id,
            Vec::new(),
        )
    }

    pub fn create_invitation_with_transport_extension(
        &mut self,
        mailbox_onion: impl Into<String>,
        meshtastic_node_id: Option<u32>,
        transport_extension: Vec<u8>,
    ) -> Result<String> {
        if transport_extension.len() > MAX_TRANSPORT_EXTENSION_SIZE {
            bail!("contact invitation transport extension is too large");
        }
        let mailbox_onion = validate_onion_address(mailbox_onion.into())?;
        // An MLS KeyPackage is single-use: processing a Welcome consumes its
        // private init key. Reusing the device's original package for several
        // invitations makes every later Welcome fail with NoMatchingKeyPackage.
        self.rotate_invitation_key_package()?;
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
            meshtastic_node_id,
            transport_extension,
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

    fn rotate_invitation_key_package(&mut self) -> Result<()> {
        let provider = provider_from_storage(self.snapshot.mls_storage.clone())?;
        let signer = read_signer(&provider, &self.snapshot.mls_signature_key)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(self.snapshot.device_id.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let key_package = KeyPackage::builder()
            .build(NYX_CIPHERSUITE, &provider, &signer, credential)
            .map_err(|error| anyhow::anyhow!("build invitation MLS KeyPackage: {error:?}"))?;
        self.snapshot.mls_key_package = key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(|error| anyhow::anyhow!("serialize invitation MLS KeyPackage: {error:?}"))?;
        self.snapshot.mls_storage = clone_storage(&provider)?;
        Ok(())
    }

    pub fn issued_invitation(&self, invitation_id: Uuid) -> Option<&IssuedInvitation> {
        self.snapshot
            .issued_invitations
            .iter()
            .find(|invitation| invitation.invitation_id == invitation_id)
    }

    pub fn issued_invitations(&self) -> &[IssuedInvitation] {
        &self.snapshot.issued_invitations
    }

    pub fn verify_invitation(encoded: &str) -> Result<ContactRecord> {
        Self::verify_invitation_with_transport_extension(encoded).map(|(contact, _)| contact)
    }

    pub fn verify_invitation_with_transport_extension(
        encoded: &str,
    ) -> Result<(ContactRecord, Vec<u8>)> {
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
        if payload.transport_extension.len() > MAX_TRANSPORT_EXTENSION_SIZE {
            bail!("contact invitation transport extension is too large");
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
        let contact = ContactRecord {
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
            meshtastic_node_id: payload.meshtastic_node_id,
        };
        Ok((contact, payload.transport_extension.clone()))
    }

    pub fn import_invitation(&mut self, encoded: &str) -> Result<ContactRecord> {
        self.import_invitation_with_transport_extension(encoded)
            .map(|(contact, _)| contact)
    }

    pub fn import_invitation_with_transport_extension(
        &mut self,
        encoded: &str,
    ) -> Result<(ContactRecord, Vec<u8>)> {
        if self.snapshot.contacts.len() >= MAX_CONTACTS {
            bail!("contact limit reached");
        }
        let (contact, transport_extension) =
            Self::verify_invitation_with_transport_extension(encoded)?;
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
        Ok((contact, transport_extension))
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

    pub fn set_contact_meshtastic_node(
        &mut self,
        device_id: Uuid,
        node_id: Option<u32>,
    ) -> Result<()> {
        let contact = self
            .snapshot
            .contacts
            .iter_mut()
            .find(|contact| contact.device_id == device_id)
            .ok_or_else(|| anyhow::anyhow!("contact does not exist"))?;
        if !contact.verified {
            bail!("contact fingerprint must be verified before binding a Meshtastic node");
        }
        contact.meshtastic_node_id = node_id;
        Ok(())
    }

    pub fn remove_contact(&mut self, device_id: Uuid) -> Result<ContactRecord> {
        let index = self
            .snapshot
            .contacts
            .iter()
            .position(|contact| contact.device_id == device_id)
            .ok_or_else(|| anyhow::anyhow!("contact does not exist"))?;
        let contact = self.snapshot.contacts.remove(index);
        self.snapshot
            .sessions
            .retain(|session| session.contact_device_id != device_id);
        self.snapshot
            .remote_pending_outbound
            .retain(|pending| pending.mailbox_token != contact.send_mailbox_token);
        Ok(contact)
    }

    /// Accept an imported invitation, create the two-member MLS group and
    /// return a signed Welcome response ready for opaque mailbox transport.
    pub fn accept_invitation(&mut self, device_id: Uuid) -> Result<Vec<u8>> {
        self.accept_invitation_with_meshtastic_node(device_id, None)
    }

    pub fn accept_invitation_with_meshtastic_node(
        &mut self,
        device_id: Uuid,
        meshtastic_node_id: Option<u32>,
    ) -> Result<Vec<u8>> {
        if self.has_session(device_id) {
            bail!("an MLS session with this contact already exists");
        }
        let contact = self
            .snapshot
            .contacts
            .iter()
            .find(|contact| contact.device_id == device_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("contact does not exist"))?;
        let provider = provider_from_storage(self.snapshot.mls_storage.clone())?;
        let signer = read_signer(&provider, &self.snapshot.mls_signature_key)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(self.snapshot.device_id.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(NYX_CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        let mut group = MlsGroup::new(&provider, &signer, &create_config, credential)
            .map_err(|error| anyhow::anyhow!("create remote MLS group: {error:?}"))?;
        let key_package =
            openmls::prelude::KeyPackageIn::tls_deserialize_exact(contact.mls_key_package.clone())
                .map_err(|error| anyhow::anyhow!("deserialize contact MLS KeyPackage: {error:?}"))?
                .validate(provider.crypto(), openmls::prelude::ProtocolVersion::Mls10)
                .map_err(|error| anyhow::anyhow!("validate contact MLS KeyPackage: {error:?}"))?;
        let (_, welcome, _) = group
            .add_members(&provider, &signer, &[key_package])
            .map_err(|error| anyhow::anyhow!("add remote MLS member: {error:?}"))?;
        group
            .merge_pending_commit(&provider)
            .map_err(|error| anyhow::anyhow!("merge remote MLS add commit: {error:?}"))?;
        let welcome = welcome
            .to_bytes()
            .map_err(|error| anyhow::anyhow!("serialize remote MLS Welcome: {error:?}"))?;
        let payload = InvitationAcceptancePayload {
            version: INVITATION_VERSION,
            invitation_id: contact.invitation_id,
            accepter_device_id: self.snapshot.device_id,
            accepter_display_name: self.snapshot.display_name.clone(),
            accepter_identity_public_key: self.snapshot.identity_public_key,
            accepter_mls_key_package: self.snapshot.mls_key_package.clone(),
            mailbox_onion: contact.mailbox_onion,
            meshtastic_node_id,
            welcome,
        };
        let encoded_payload = postcard::to_allocvec(&payload).context("serialize acceptance")?;
        let signature = SigningKey::from_bytes(&self.snapshot.identity_secret_key)
            .sign(&encoded_payload)
            .to_bytes()
            .to_vec();
        let group_id = group.group_id().as_slice().to_vec();
        self.snapshot.mls_storage = clone_storage(&provider)?;
        self.snapshot.sessions.push(RemoteSession {
            invitation_id: payload.invitation_id,
            contact_device_id: device_id,
            group_id,
        });
        postcard::to_allocvec(&SignedInvitationAcceptance { payload, signature })
            .context("serialize signed invitation acceptance")
    }

    /// Verify a signed acceptance for one of our issued invitations and join
    /// the MLS group using the private KeyPackage material in this identity.
    pub fn process_invitation_acceptance(&mut self, encoded: &[u8]) -> Result<ContactRecord> {
        let acceptance: SignedInvitationAcceptance =
            postcard::from_bytes(encoded).context("deserialize invitation acceptance")?;
        let payload = &acceptance.payload;
        if payload.version != INVITATION_VERSION {
            bail!("invitation acceptance version is unsupported");
        }
        validate_display_name(payload.accepter_display_name.clone())?;
        validate_onion_address(payload.mailbox_onion.clone())?;
        let issued = self
            .issued_invitation(payload.invitation_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("acceptance references an unknown invitation"))?;
        if issued.expires_unix_ms <= unix_time_ms()? {
            bail!("acceptance references an expired invitation");
        }
        if self.has_session(payload.accepter_device_id) {
            return self
                .snapshot
                .contacts
                .iter()
                .find(|contact| contact.device_id == payload.accepter_device_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("existing MLS session has no contact"));
        }
        let key = VerifyingKey::from_bytes(&payload.accepter_identity_public_key)
            .context("acceptance identity key is invalid")?;
        let signature: [u8; 64] = acceptance
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("acceptance signature has invalid length"))?;
        key.verify(
            &postcard::to_allocvec(payload).context("serialize acceptance")?,
            &Signature::from_bytes(&signature),
        )
        .context("invitation acceptance signature verification failed")?;
        let provider = provider_from_storage(self.snapshot.mls_storage.clone())?;
        let accepter_key_package = openmls::prelude::KeyPackageIn::tls_deserialize_exact(
            payload.accepter_mls_key_package.clone(),
        )
        .map_err(|error| anyhow::anyhow!("deserialize accepter MLS KeyPackage: {error:?}"))?
        .validate(provider.crypto(), openmls::prelude::ProtocolVersion::Mls10)
        .map_err(|error| anyhow::anyhow!("validate accepter MLS KeyPackage: {error:?}"))?;
        if accepter_key_package.ciphersuite() != NYX_CIPHERSUITE {
            bail!("invitation acceptance uses an unsupported MLS ciphersuite");
        }
        let message = MlsMessageIn::tls_deserialize_exact(payload.welcome.clone())
            .map_err(|error| anyhow::anyhow!("deserialize MLS Welcome: {error:?}"))?;
        let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
            bail!("invitation acceptance does not contain an MLS Welcome");
        };
        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let group = StagedWelcome::new_from_welcome(&provider, &join_config, welcome, None)
            .map_err(|error| anyhow::anyhow!("process remote MLS Welcome: {error:?}"))?
            .into_group(&provider)
            .map_err(|error| anyhow::anyhow!("join remote MLS group: {error:?}"))?;
        let contact = ContactRecord {
            invitation_id: payload.invitation_id,
            device_id: payload.accepter_device_id,
            display_name: payload.accepter_display_name.clone(),
            identity_public_key: payload.accepter_identity_public_key,
            identity_fingerprint: fingerprint(&payload.accepter_identity_public_key),
            mls_key_package: payload.accepter_mls_key_package.clone(),
            mailbox_onion: payload.mailbox_onion.clone(),
            send_mailbox_token: issued.invitee_receive_token,
            receive_mailbox_token: issued.inviter_receive_token,
            verified: false,
            meshtastic_node_id: payload.meshtastic_node_id,
        };
        self.snapshot.mls_storage = clone_storage(&provider)?;
        self.snapshot.sessions.push(RemoteSession {
            invitation_id: payload.invitation_id,
            contact_device_id: payload.accepter_device_id,
            group_id: group.group_id().as_slice().to_vec(),
        });
        self.snapshot.contacts.push(contact.clone());
        Ok(contact)
    }

    pub fn encrypt_for_contact(&mut self, device_id: Uuid, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.is_empty() {
            bail!("MLS application message must not be empty");
        }
        let session = self
            .snapshot
            .sessions
            .iter()
            .find(|session| session.contact_device_id == device_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("remote MLS session is not established"))?;
        let provider = provider_from_storage(self.snapshot.mls_storage.clone())?;
        let signer = read_signer(&provider, &self.snapshot.mls_signature_key)?;
        let group_id = openmls::prelude::GroupId::from_slice(&session.group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| anyhow::anyhow!("load remote MLS group: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("remote MLS group is missing"))?;
        let ciphertext = group
            .create_message(&provider, &signer, plaintext)
            .map_err(|error| anyhow::anyhow!("encrypt remote MLS message: {error:?}"))?
            .to_bytes()
            .map_err(|error| anyhow::anyhow!("serialize remote MLS message: {error:?}"))?;
        self.snapshot.mls_storage = clone_storage(&provider)?;
        Ok(ciphertext)
    }

    pub fn decrypt_from_contact(&mut self, device_id: Uuid, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let session = self
            .snapshot
            .sessions
            .iter()
            .find(|session| session.contact_device_id == device_id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("remote MLS session is not established"))?;
        let provider = provider_from_storage(self.snapshot.mls_storage.clone())?;
        let group_id = openmls::prelude::GroupId::from_slice(&session.group_id);
        let mut group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|error| anyhow::anyhow!("load remote MLS group: {error:?}"))?
            .ok_or_else(|| anyhow::anyhow!("remote MLS group is missing"))?;
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|error| anyhow::anyhow!("deserialize remote MLS message: {error:?}"))?
            .try_into_protocol_message()
            .map_err(|error| anyhow::anyhow!("expected an MLS protocol message: {error:?}"))?;
        let processed = group
            .process_message(&provider, message)
            .map_err(|error| anyhow::anyhow!("decrypt remote MLS message: {error:?}"))?;
        let ProcessedMessageContent::ApplicationMessage(message) = processed.into_content() else {
            bail!("received MLS message is not application data");
        };
        self.snapshot.mls_storage = clone_storage(&provider)?;
        Ok(message.into_bytes())
    }

    pub fn process_remote_inbound_and_save(
        &mut self,
        device_id: Uuid,
        ciphertext: &[u8],
        receipt: [u8; 32],
        expires_unix_ms: i64,
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<Vec<u8>> {
        if self.has_remote_inbound_receipt(&receipt) {
            bail!("inbound mailbox receipt was already processed");
        }
        let before = postcard::to_allocvec(&self.snapshot).context("snapshot device identity")?;
        let plaintext = self.decrypt_from_contact(device_id, ciphertext)?;
        let now = unix_time_ms()?;
        self.snapshot
            .remote_inbound_receipts
            .retain(|entry| entry.expires_unix_ms > now);
        if self.snapshot.remote_inbound_receipts.len() >= MAX_INBOUND_RECEIPTS {
            self.snapshot = postcard::from_bytes(&before).context("restore device identity")?;
            bail!("remote inbound receipt journal is full");
        }
        self.snapshot.remote_inbound_receipts.push(InboundReceipt {
            receipt,
            expires_unix_ms,
        });
        if let Err(error) = self.save_encrypted(path, password) {
            self.snapshot = postcard::from_bytes(&before)
                .context("restore device identity after failed inbound safe-save")?;
            return Err(error);
        }
        Ok(plaintext)
    }

    pub fn create_remote_outbound_and_save(
        &mut self,
        device_id: Uuid,
        plaintext: &[u8],
        mailbox_token: [u8; 32],
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<PendingOutbound> {
        if self.snapshot.remote_pending_outbound.len() >= MAX_OUTBOUND_JOURNAL {
            bail!("remote outbound journal is full");
        }
        let before = postcard::to_allocvec(&self.snapshot).context("snapshot device identity")?;
        let mls_ciphertext = self.encrypt_for_contact(device_id, plaintext)?;
        let ciphertext =
            nyx_protocol::encode_client_payload(&nyx_protocol::ClientPayload::MlsApplication {
                sender_device: self.snapshot.device_id,
                ciphertext: mls_ciphertext,
            })
            .map_err(|error| anyhow::anyhow!("serialize remote client payload: {error}"))?;
        let pending = PendingOutbound {
            id: Uuid::new_v4(),
            mailbox_token,
            ciphertext,
        };
        self.snapshot.remote_pending_outbound.push(pending.clone());
        if let Err(error) = self.save_encrypted(path, password) {
            self.snapshot = postcard::from_bytes(&before)
                .context("restore device identity after failed outbound safe-save")?;
            return Err(error);
        }
        Ok(pending)
    }

    pub fn journal_remote_payload_and_save(
        &mut self,
        ciphertext: Vec<u8>,
        mailbox_token: [u8; 32],
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<PendingOutbound> {
        if self.snapshot.remote_pending_outbound.len() >= MAX_OUTBOUND_JOURNAL {
            bail!("remote outbound journal is full");
        }
        let pending = PendingOutbound {
            id: Uuid::new_v4(),
            mailbox_token,
            ciphertext,
        };
        self.snapshot.remote_pending_outbound.push(pending.clone());
        if let Err(error) = self.save_encrypted(path, password) {
            self.snapshot.remote_pending_outbound.pop();
            return Err(error);
        }
        Ok(pending)
    }

    pub fn mark_remote_outbound_queued_and_save(
        &mut self,
        id: Uuid,
        path: impl AsRef<Path>,
        password: &[u8],
    ) -> Result<()> {
        let index = self
            .snapshot
            .remote_pending_outbound
            .iter()
            .position(|pending| pending.id == id)
            .ok_or_else(|| anyhow::anyhow!("remote outbound journal entry does not exist"))?;
        let pending = self.snapshot.remote_pending_outbound.remove(index);
        if let Err(error) = self.save_encrypted(path, password) {
            self.snapshot.remote_pending_outbound.insert(index, pending);
            return Err(error);
        }
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
        let snapshot: DeviceIdentitySnapshot = postcard::from_bytes(&encoded)
            .or_else(|error| {
                postcard::from_bytes::<PreviousDeviceIdentitySnapshot>(&encoded)
                    .map(Into::into)
                    .map_err(|_| error)
            })
            .or_else(|error| {
                postcard::from_bytes::<LegacyDeviceIdentitySnapshot>(&encoded)
                    .map(Into::into)
                    .map_err(|_| error)
            })
            .or_else(|error| {
                postcard::from_bytes::<OriginalDeviceIdentitySnapshot>(&encoded)
                    .map(Into::into)
                    .map_err(|_| error)
            })
            .context("deserialize device identity")?;
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
    fn loads_identity_snapshot_created_before_remote_sessions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy-identity.nyx");
        let identity = DeviceIdentity::generate("Alice").unwrap();
        let legacy = OriginalDeviceIdentitySnapshot {
            version: identity.snapshot.version,
            device_id: identity.snapshot.device_id,
            display_name: identity.snapshot.display_name.clone(),
            identity_secret_key: identity.snapshot.identity_secret_key,
            identity_public_key: identity.snapshot.identity_public_key,
            mls_signature_key: identity.snapshot.mls_signature_key.clone(),
            mls_storage: identity.snapshot.mls_storage.clone(),
            mls_key_package: identity.snapshot.mls_key_package.clone(),
            contacts: identity
                .snapshot
                .contacts
                .clone()
                .into_iter()
                .map(Into::into)
                .collect(),
            issued_invitations: identity.snapshot.issued_invitations.clone(),
        };
        let encoded = postcard::to_allocvec(&legacy).unwrap();
        nyx_store::EncryptedBlobStore::save(&path, b"strong local password", &encoded).unwrap();

        let restored = DeviceIdentity::load_encrypted(&path, b"strong local password").unwrap();
        assert_eq!(restored.device_id(), identity.device_id());
        assert!(restored.sessions().is_empty());
        assert!(restored.remote_pending_outbound().is_empty());
    }

    #[test]
    fn signed_contact_invitation_verifies_key_package_and_directions() {
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let invitation = alice
            .create_invitation_with_transport_extension(
                "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion",
                Some(0xa1b2c3d4),
                b"signed opaque transport bootstrap".to_vec(),
            )
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
        assert_eq!(contact.meshtastic_node_id, Some(0xa1b2c3d4));
        let (_, transport) =
            DeviceIdentity::verify_invitation_with_transport_extension(&invitation).unwrap();
        assert_eq!(transport, b"signed opaque transport bootstrap");
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
        bob.set_contact_meshtastic_node(contact.device_id, Some(0xa1b2c3d4))
            .unwrap();
        bob.save_encrypted(&path, b"strong local password").unwrap();

        let restored = DeviceIdentity::load_encrypted(&path, b"strong local password").unwrap();
        assert_eq!(restored.contacts().len(), 1);
        assert!(restored.contacts()[0].verified);
        assert_eq!(restored.contacts()[0].device_id, alice.device_id());
        assert_eq!(restored.contacts()[0].meshtastic_node_id, Some(0xa1b2c3d4));
    }

    #[test]
    fn removed_contact_can_be_imported_again() {
        let onion = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let invitation = alice.create_invitation(onion).unwrap();
        let mut bob = DeviceIdentity::generate("Bob").unwrap();
        let contact = bob.import_invitation(&invitation).unwrap();
        bob.mark_contact_verified(contact.device_id).unwrap();
        bob.accept_invitation(contact.device_id).unwrap();

        let removed = bob.remove_contact(contact.device_id).unwrap();
        assert_eq!(removed.device_id, contact.device_id);
        assert!(bob.contacts().is_empty());
        assert!(!bob.has_session(contact.device_id));

        let replacement = alice.create_invitation(onion).unwrap();
        assert_eq!(
            bob.import_invitation(&replacement).unwrap().device_id,
            contact.device_id
        );
    }

    #[test]
    fn signed_acceptance_establishes_persistent_remote_mls_session() {
        let onion = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let invitation = alice.create_invitation(onion).unwrap();
        let mut bob = DeviceIdentity::generate("Bob").unwrap();
        bob.import_invitation(&invitation).unwrap();

        let acceptance = bob
            .accept_invitation_with_meshtastic_node(alice.device_id(), Some(0x9e7638c4))
            .unwrap();
        let bob_contact = alice.process_invitation_acceptance(&acceptance).unwrap();
        assert!(alice.has_session(bob.device_id()));
        assert!(bob.has_session(alice.device_id()));
        assert_eq!(
            bob.contacts()[0].send_mailbox_token,
            bob_contact.receive_mailbox_token
        );
        assert_eq!(
            bob.contacts()[0].receive_mailbox_token,
            bob_contact.send_mailbox_token
        );
        assert_eq!(bob_contact.meshtastic_node_id, Some(0x9e7638c4));

        let encrypted = bob
            .encrypt_for_contact(alice.device_id(), b"hello alice")
            .unwrap();
        assert_eq!(
            alice
                .decrypt_from_contact(bob.device_id(), &encrypted)
                .unwrap(),
            b"hello alice"
        );
        let reply = alice
            .encrypt_for_contact(bob.device_id(), b"hello bob")
            .unwrap();
        assert_eq!(
            bob.decrypt_from_contact(alice.device_id(), &reply).unwrap(),
            b"hello bob"
        );
    }

    #[test]
    fn every_invitation_uses_a_distinct_joinable_key_package() {
        let onion = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        let mut alice = DeviceIdentity::generate("Alice").unwrap();
        let first_invitation = alice.create_invitation(onion).unwrap();
        let second_invitation = alice.create_invitation(onion).unwrap();

        let first_payload = DeviceIdentity::verify_invitation(&first_invitation).unwrap();
        let second_payload = DeviceIdentity::verify_invitation(&second_invitation).unwrap();
        assert_ne!(
            first_payload.mls_key_package,
            second_payload.mls_key_package
        );

        let mut bob = DeviceIdentity::generate("Bob").unwrap();
        let bob_contact = bob.import_invitation(&first_invitation).unwrap();
        let bob_acceptance = bob.accept_invitation(bob_contact.device_id).unwrap();

        let mut carol = DeviceIdentity::generate("Carol").unwrap();
        let carol_contact = carol.import_invitation(&second_invitation).unwrap();
        let carol_acceptance = carol.accept_invitation(carol_contact.device_id).unwrap();

        alice
            .process_invitation_acceptance(&bob_acceptance)
            .unwrap();
        alice
            .process_invitation_acceptance(&carol_acceptance)
            .unwrap();
        assert!(alice.has_session(bob.device_id()));
        assert!(alice.has_session(carol.device_id()));
    }

    #[test]
    fn mailbox_removal_preserves_an_active_endpoint() {
        let first = "25njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        let second = "35njqamcweflpvkl73j4szahhihoc4xt3ktcgjnpaingr5yhkenl5sid.onion";
        let mut identity = DeviceIdentity::generate("Alice").unwrap();
        identity.add_mailbox(first).unwrap();
        assert!(identity.remove_mailbox_address(first).is_err());
        assert_eq!(identity.mailbox_onion(), Some(first));

        identity.add_mailbox(second).unwrap();
        identity.remove_mailbox_address(first).unwrap();
        assert_eq!(identity.mailboxes(), &[second.to_owned()]);
        assert_eq!(identity.mailbox_onion(), Some(second));
        assert!(identity.remove_mailbox_address(first).is_err());
    }
}
