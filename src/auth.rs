use crate::db::DbConnection;
use bcrypt::{hash, verify, DEFAULT_COST};
use chrono::Utc;
use rand::Rng;
use rusqlite::params;
use uuid::Uuid;

pub fn hash_password(password: &str) -> String {
    hash(password, DEFAULT_COST).unwrap()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    verify(password, hash).unwrap_or(false)
}

pub fn generate_token() -> String {
    rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

pub async fn create_auth_token(conn: &DbConnection, user_id: &Uuid) -> Result<String, rusqlite::Error> {
    let token = generate_token();
    let now = Utc::now();

    conn.lock().await.execute(
        "INSERT INTO auth_tokens (token, user_id, created_at) VALUES (?, ?, ?)",
        params![token, user_id.to_string(), now.to_rfc3339()],
    )?;

    Ok(token)
}

pub async fn verify_auth_token(conn: &DbConnection, token: &str) -> Result<Uuid, rusqlite::Error> {
    conn.lock().await.query_row(
        "SELECT user_id FROM auth_tokens WHERE token = ?",
        [token],
        |row| {
            let user_id: String = row.get(0)?;
            Ok(Uuid::parse_str(&user_id).unwrap())
        },
    )
}