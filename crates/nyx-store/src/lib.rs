use anyhow::{Context, Result, bail};
use argon2::Argon2;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::Connection;
use std::{
    fs,
    io::{Read, Write},
    path::Path,
};
use zeroize::Zeroizing;

const ENCRYPTED_MAGIC: &[u8; 4] = b"NYXE";
const ENCRYPTED_VERSION: u8 = 1;
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;
const HEADER_SIZE: usize = ENCRYPTED_MAGIC.len() + 1 + SALT_SIZE + NONCE_SIZE;
const MAX_PLAINTEXT_SIZE: usize = 64 * 1024 * 1024;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS kv (
                k TEXT PRIMARY KEY NOT NULL,
                v BLOB NOT NULL
            );
            "#,
        )?;
        Ok(Self { conn })
    }

    pub fn is_open(&self) -> bool {
        self.conn.is_autocommit()
    }
}

/// Password-encrypted, authenticated blob persistence.
///
/// Files use Argon2id for key derivation and XChaCha20-Poly1305 for AEAD. The
/// header is authenticated as associated data, and saves replace the target
/// atomically after syncing a same-directory temporary file.
pub struct EncryptedBlobStore;

impl EncryptedBlobStore {
    pub fn save(path: impl AsRef<Path>, password: &[u8], plaintext: &[u8]) -> Result<()> {
        validate_inputs(password, plaintext.len())?;
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).context("create encrypted-store directory")?;

        let mut salt = [0_u8; SALT_SIZE];
        let mut nonce = [0_u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce);
        let key = derive_key(password, &salt)?;

        let mut header = Vec::with_capacity(HEADER_SIZE);
        header.extend_from_slice(ENCRYPTED_MAGIC);
        header.push(ENCRYPTED_VERSION);
        header.extend_from_slice(&salt);
        header.extend_from_slice(&nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("initialize encrypted store cipher"))?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypt local store"))?;

        let mut temporary = tempfile::NamedTempFile::new_in(parent)
            .context("create encrypted-store temporary file")?;
        set_owner_only_permissions(temporary.as_file())?;
        temporary.write_all(&header)?;
        temporary.write_all(&ciphertext)?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| error.error)
            .context("atomically replace encrypted store")?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>, password: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if password.is_empty() {
            bail!("encrypted-store password must not be empty");
        }
        let mut file = fs::File::open(path).context("open encrypted store")?;
        let metadata = file.metadata()?;
        let maximum_file_size = HEADER_SIZE
            .saturating_add(MAX_PLAINTEXT_SIZE)
            .saturating_add(16);
        if metadata.len() > maximum_file_size as u64 {
            bail!("encrypted store exceeds maximum size");
        }
        let mut encoded = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut encoded)?;
        if encoded.len() < HEADER_SIZE + 16 {
            bail!("encrypted store is truncated");
        }
        if &encoded[..ENCRYPTED_MAGIC.len()] != ENCRYPTED_MAGIC {
            bail!("encrypted store has invalid magic");
        }
        if encoded[ENCRYPTED_MAGIC.len()] != ENCRYPTED_VERSION {
            bail!("encrypted store version is unsupported");
        }

        let salt_start = ENCRYPTED_MAGIC.len() + 1;
        let nonce_start = salt_start + SALT_SIZE;
        let ciphertext_start = nonce_start + NONCE_SIZE;
        let salt = &encoded[salt_start..nonce_start];
        let nonce = &encoded[nonce_start..ciphertext_start];
        let key = derive_key(password, salt)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| anyhow::anyhow!("initialize encrypted store cipher"))?;
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &encoded[ciphertext_start..],
                    aad: &encoded[..ciphertext_start],
                },
            )
            .map_err(|_| anyhow::anyhow!("encrypted store authentication failed"))?;
        if plaintext.len() > MAX_PLAINTEXT_SIZE {
            bail!("decrypted store exceeds maximum size");
        }
        Ok(Zeroizing::new(plaintext))
    }
}

fn validate_inputs(password: &[u8], plaintext_size: usize) -> Result<()> {
    if password.is_empty() {
        bail!("encrypted-store password must not be empty");
    }
    if plaintext_size > MAX_PLAINTEXT_SIZE {
        bail!("encrypted-store plaintext exceeds maximum size");
    }
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::default()
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| anyhow::anyhow!("derive encrypted-store key"))?;
    Ok(key)
}

#[cfg(unix)]
fn set_owner_only_permissions(file: &fs::File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_file: &fs::File) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_blob_round_trip_and_replace() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.nyx");
        EncryptedBlobStore::save(&path, b"correct horse battery staple", b"first").unwrap();
        assert_eq!(
            EncryptedBlobStore::load(&path, b"correct horse battery staple")
                .unwrap()
                .as_slice(),
            b"first"
        );
        EncryptedBlobStore::save(&path, b"correct horse battery staple", b"second").unwrap();
        assert_eq!(
            EncryptedBlobStore::load(&path, b"correct horse battery staple")
                .unwrap()
                .as_slice(),
            b"second"
        );
    }

    #[test]
    fn wrong_password_and_tampering_are_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.nyx");
        EncryptedBlobStore::save(&path, b"password", b"sensitive state").unwrap();
        assert!(EncryptedBlobStore::load(&path, b"wrong").is_err());

        let mut encoded = fs::read(&path).unwrap();
        let last = encoded.len() - 1;
        encoded[last] ^= 1;
        fs::write(&path, encoded).unwrap();
        assert!(EncryptedBlobStore::load(&path, b"password").is_err());
    }

    #[test]
    fn empty_password_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.nyx");
        assert!(EncryptedBlobStore::save(path, b"", b"state").is_err());
    }
}
