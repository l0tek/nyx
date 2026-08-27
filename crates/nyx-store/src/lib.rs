use anyhow::Result;
use rusqlite::Connection;
use std::path::Path;

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
