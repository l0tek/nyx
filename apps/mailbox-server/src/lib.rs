use anyhow::{Context, Result};
use nyx_protocol::{
    Envelope, MAX_CIPHERTEXT_SIZE, MAX_FETCH_MESSAGES, MailboxErrorCode, MailboxRequest,
    MailboxResponse, PROTOCOL_VERSION, StoredEnvelope, envelope_receipt,
};
use rusqlite::{Connection, OptionalExtension, params};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const DEFAULT_RETENTION: Duration = Duration::from_secs(7 * 24 * 60 * 60);
pub const MAX_MESSAGES_PER_MAILBOX: i64 = 1024;

/// Persistent storage for opaque envelopes. The server never parses ciphertext.
pub struct MailboxStore {
    connection: Mutex<Connection>,
    retention: Duration,
}

impl MailboxStore {
    pub fn open(path: impl AsRef<std::path::Path>, retention: Duration) -> Result<Self> {
        let connection = Connection::open(path).context("open mailbox database")?;
        Self::from_connection(connection, retention)
    }

    pub fn open_in_memory(retention: Duration) -> Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, retention)
    }

    fn from_connection(connection: Connection, retention: Duration) -> Result<Self> {
        connection.execute_batch(
            r#"
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS envelopes (
                receipt BLOB PRIMARY KEY NOT NULL CHECK(length(receipt) = 32),
                mailbox_token BLOB NOT NULL CHECK(length(mailbox_token) = 32),
                version INTEGER NOT NULL,
                ciphertext BLOB NOT NULL,
                created_unix_ms INTEGER NOT NULL,
                expires_unix_ms INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS envelopes_mailbox_created
                ON envelopes(mailbox_token, created_unix_ms);
            CREATE INDEX IF NOT EXISTS envelopes_expiry
                ON envelopes(expires_unix_ms);
            "#,
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
            retention,
        })
    }

    pub fn handle(&self, request: MailboxRequest) -> MailboxResponse {
        match self.try_handle(request) {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(error = %error, "mailbox storage operation failed");
                MailboxResponse::Error(MailboxErrorCode::ServerBusy)
            }
        }
    }

    fn try_handle(&self, request: MailboxRequest) -> Result<MailboxResponse> {
        let now = now_unix_ms()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| anyhow::anyhow!("mailbox database lock poisoned"))?;
        connection.execute("DELETE FROM envelopes WHERE expires_unix_ms <= ?1", [now])?;

        match request {
            MailboxRequest::Deposit(envelope) => self.deposit(&mut connection, envelope, now),
            MailboxRequest::Fetch {
                mailbox_token,
                limit,
            } => self.fetch(&connection, mailbox_token, limit, now),
            MailboxRequest::Acknowledge {
                mailbox_token,
                receipts,
            } => self.acknowledge(&mut connection, mailbox_token, receipts),
        }
    }

    fn deposit(
        &self,
        connection: &mut Connection,
        envelope: Envelope,
        now: i64,
    ) -> Result<MailboxResponse> {
        if envelope.version != PROTOCOL_VERSION {
            return Ok(MailboxResponse::Error(MailboxErrorCode::InvalidVersion));
        }
        if envelope.ciphertext.len() > MAX_CIPHERTEXT_SIZE {
            return Ok(MailboxResponse::Error(MailboxErrorCode::MessageTooLarge));
        }

        let receipt = envelope_receipt(&envelope)?;
        let expires = now.saturating_add(self.retention.as_millis().min(i64::MAX as u128) as i64);
        let transaction = connection.transaction()?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT 1 FROM envelopes WHERE receipt = ?1",
                [receipt.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if existing.is_none() {
            let count: i64 = transaction.query_row(
                "SELECT count(*) FROM envelopes WHERE mailbox_token = ?1",
                [envelope.mailbox_token.as_slice()],
                |row| row.get(0),
            )?;
            if count >= MAX_MESSAGES_PER_MAILBOX {
                return Ok(MailboxResponse::Error(MailboxErrorCode::ServerBusy));
            }
            transaction.execute(
                "INSERT INTO envelopes (receipt, mailbox_token, version, ciphertext, created_unix_ms, expires_unix_ms) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    receipt.as_slice(),
                    envelope.mailbox_token.as_slice(),
                    i64::from(envelope.version),
                    envelope.ciphertext,
                    now,
                    expires,
                ],
            )?;
        }
        transaction.commit()?;
        Ok(MailboxResponse::Deposited { receipt })
    }

    fn fetch(
        &self,
        connection: &Connection,
        mailbox_token: [u8; 32],
        limit: u16,
        now: i64,
    ) -> Result<MailboxResponse> {
        if limit == 0 || limit > MAX_FETCH_MESSAGES {
            return Ok(MailboxResponse::Error(MailboxErrorCode::InvalidLimit));
        }
        let mut statement = connection.prepare(
            "SELECT receipt, version, ciphertext, expires_unix_ms FROM envelopes WHERE mailbox_token = ?1 AND expires_unix_ms > ?2 ORDER BY created_unix_ms, receipt LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![mailbox_token.as_slice(), now, i64::from(limit)],
            |row| {
                let receipt: Vec<u8> = row.get(0)?;
                let version: u16 = row.get(1)?;
                let ciphertext: Vec<u8> = row.get(2)?;
                let expires_unix_ms = row.get(3)?;
                Ok((receipt, version, ciphertext, expires_unix_ms))
            },
        )?;
        let mut messages = Vec::new();
        let mut response_budget = 0_usize;
        for row in rows {
            let (receipt, version, ciphertext, expires_unix_ms) = row?;
            let estimated_size = ciphertext.len().saturating_add(128);
            if response_budget.saturating_add(estimated_size) > MAX_CIPHERTEXT_SIZE {
                break;
            }
            let receipt: [u8; 32] = receipt
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid receipt length in database"))?;
            messages.push(StoredEnvelope {
                receipt,
                envelope: Envelope {
                    version,
                    mailbox_token,
                    ciphertext,
                },
                expires_unix_ms,
            });
            response_budget = response_budget.saturating_add(estimated_size);
        }
        Ok(MailboxResponse::Messages(messages))
    }

    fn acknowledge(
        &self,
        connection: &mut Connection,
        mailbox_token: [u8; 32],
        receipts: Vec<[u8; 32]>,
    ) -> Result<MailboxResponse> {
        if receipts.len() > usize::from(MAX_FETCH_MESSAGES) {
            return Ok(MailboxResponse::Error(MailboxErrorCode::InvalidLimit));
        }
        let transaction = connection.transaction()?;
        let mut deleted = 0_u16;
        for receipt in receipts {
            deleted = deleted.saturating_add(transaction.execute(
                "DELETE FROM envelopes WHERE mailbox_token = ?1 AND receipt = ?2",
                params![mailbox_token.as_slice(), receipt.as_slice()],
            )? as u16);
        }
        transaction.commit()?;
        Ok(MailboxResponse::Acknowledged { deleted })
    }
}

fn now_unix_ms() -> Result<i64> {
    let millis = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    i64::try_from(millis).context("system time does not fit in i64")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn envelope(token: u8, ciphertext: &[u8]) -> Envelope {
        Envelope {
            version: PROTOCOL_VERSION,
            mailbox_token: [token; 32],
            ciphertext: ciphertext.to_vec(),
        }
    }

    #[test]
    fn deposit_fetch_and_acknowledge() {
        let store = MailboxStore::open_in_memory(DEFAULT_RETENTION).unwrap();
        let deposited = store.handle(MailboxRequest::Deposit(envelope(7, b"ciphertext")));
        let receipt = match deposited {
            MailboxResponse::Deposited { receipt } => receipt,
            other => panic!("unexpected response: {other:?}"),
        };

        let fetched = store.handle(MailboxRequest::Fetch {
            mailbox_token: [7; 32],
            limit: 10,
        });
        assert!(matches!(fetched, MailboxResponse::Messages(ref values) if values.len() == 1));

        let acknowledged = store.handle(MailboxRequest::Acknowledge {
            mailbox_token: [7; 32],
            receipts: vec![receipt],
        });
        assert!(matches!(
            acknowledged,
            MailboxResponse::Acknowledged { deleted: 1 }
        ));
        let fetched = store.handle(MailboxRequest::Fetch {
            mailbox_token: [7; 32],
            limit: 10,
        });
        assert!(matches!(fetched, MailboxResponse::Messages(ref values) if values.is_empty()));
    }

    #[test]
    fn acknowledgement_cannot_cross_mailboxes() {
        let store = MailboxStore::open_in_memory(DEFAULT_RETENTION).unwrap();
        let receipt = match store.handle(MailboxRequest::Deposit(envelope(1, b"secret"))) {
            MailboxResponse::Deposited { receipt } => receipt,
            other => panic!("unexpected response: {other:?}"),
        };
        let response = store.handle(MailboxRequest::Acknowledge {
            mailbox_token: [2; 32],
            receipts: vec![receipt],
        });
        assert!(matches!(
            response,
            MailboxResponse::Acknowledged { deleted: 0 }
        ));
    }

    #[test]
    fn invalid_inputs_are_rejected() {
        let store = MailboxStore::open_in_memory(DEFAULT_RETENTION).unwrap();
        let mut wrong_version = envelope(1, b"x");
        wrong_version.version += 1;
        assert!(matches!(
            store.handle(MailboxRequest::Deposit(wrong_version)),
            MailboxResponse::Error(MailboxErrorCode::InvalidVersion)
        ));
        assert!(matches!(
            store.handle(MailboxRequest::Fetch {
                mailbox_token: [1; 32],
                limit: 0
            }),
            MailboxResponse::Error(MailboxErrorCode::InvalidLimit)
        ));
    }
}
