use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: Uuid,
    pub display_name: String,
    pub identity_fingerprint: String,
    pub verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub id: Uuid,
    pub conversation_id: Uuid,
    pub body: String,
    pub created_unix_ms: i64,
}

impl ChatMessage {
    pub fn new(conversation_id: Uuid, body: impl Into<String>, created_unix_ms: i64) -> Self {
        Self {
            id: Uuid::new_v4(),
            conversation_id,
            body: body.into(),
            created_unix_ms,
        }
    }
}
