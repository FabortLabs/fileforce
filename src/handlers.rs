use crate::auth::{create_auth_token, hash_password, verify_auth_token, verify_password};
use crate::db::DbConnection;
use crate::models::{File, User};
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use chrono::{DateTime, Utc};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio::sync::Mutex;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

#[derive(Deserialize)]
pub struct RegisterUser {
    username: String,
    email: String,
    password: String,
}

#[derive(Deserialize)]
pub struct LoginUser {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct AuthToken {
    token: String,
}

pub async fn register_user(
    State(conn): State<DbConnection>,
    Json(user_data): Json<RegisterUser>,
) -> impl IntoResponse {
    let password_hash = hash_password(&user_data.password);
    let id = Uuid::new_v4();
    let now = Utc::now();

    let result = conn.lock().await.execute(
        "INSERT INTO users (id, username, email, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        params![
            id.to_string(),
            user_data.username,
            user_data.email,
            password_hash,
            now.to_rfc3339(),
            now.to_rfc3339()
        ],
    );

    match result {
        Ok(_) => {
            let token = create_auth_token(&conn, &id).await.unwrap();
            (StatusCode::CREATED, Json(AuthToken { token })).into_response()
        }
        Err(_) => (StatusCode::BAD_REQUEST, "User already exists").into_response(),
    }
}

pub async fn login_user(
    State(conn): State<DbConnection>,
    Json(login_data): Json<LoginUser>,
) -> impl IntoResponse {
    let user_result = conn.lock().await.query_row(
        "SELECT id, password_hash FROM users WHERE username = ?",
        [&login_data.username],
        |row| {
            Ok((
                Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                row.get::<_, String>(1)?,
            ))
        },
    );

    match user_result {
        Ok((user_id, password_hash)) => {
            if verify_password(&login_data.password, &password_hash) {
                let token = create_auth_token(&conn, &user_id).await.unwrap();
                (StatusCode::OK, Json(AuthToken { token })).into_response()
            } else {
                (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response()
            }
        }
        Err(_) => (StatusCode::UNAUTHORIZED, "Invalid credentials").into_response(),
    }
}

pub async fn upload_file(
    State(conn): State<DbConnection>,
    headers: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let token = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    let user_id = match token {
        Some(token) => match verify_auth_token(&conn, token).await {
            Ok(user_id) => user_id,
            Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
        },
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    while let Some(field) = multipart.next_field().await.unwrap() {
        let filename = field.file_name().unwrap().to_string();
        let data = field.bytes().await.unwrap();

        let file_path = format!("files/{}/{}", user_id, filename);
        tokio::fs::create_dir_all(format!("files/{}", user_id))
            .await
            .unwrap();
        tokio::fs::write(&file_path, &data).await.unwrap();

        let id = Uuid::new_v4();
        let now = Utc::now();

        conn.lock().await.execute(
            "INSERT INTO files (id, user_id, filename, file_path, is_public, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                id.to_string(),
                user_id.to_string(),
                filename,
                file_path,
                false,
                now.to_rfc3339(),
                now.to_rfc3339()
            ],
        ).unwrap();

        return (StatusCode::CREATED, "File uploaded successfully").into_response();
    }

    (StatusCode::BAD_REQUEST, "No file uploaded").into_response()
}

pub async fn get_user_files(
    State(conn): State<DbConnection>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let token = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    let user_id = match token {
        Some(token) => match verify_auth_token(&conn, token).await {
            Ok(user_id) => user_id,
            Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
        },
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    let conn = conn.lock().await;
    let mut stmt = match conn.prepare("SELECT id, user_id, filename, file_path, is_public, public_url, created_at, updated_at FROM files WHERE user_id = ?") {
        Ok(stmt) => stmt,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to prepare statement").into_response(),
    };

    let files_result = stmt.query_map([user_id.to_string()], |row| {
        Ok(File {
            id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
            user_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap(),
            filename: row.get(2)?,
            file_path: row.get(3)?,
            is_public: row.get(4)?,
            public_url: row.get(5)?,
            created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&Utc),
        })
    });

    match files_result {
        Ok(files) => {
            let collected: Result<Vec<_>, _> = files.collect();
            match collected {
                Ok(files) => (StatusCode::OK, Json(files)).into_response(),
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to process files").into_response(),
            }
        },
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch files").into_response(),
    }
}


pub async fn make_file_public(
    State(conn): State<DbConnection>,
    headers: HeaderMap,
    Path(file_id): Path<Uuid>,
) -> impl IntoResponse {
    let token = headers
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    let user_id = match token {
        Some(token) => match verify_auth_token(&conn, token).await {
            Ok(user_id) => user_id,
            Err(_) => return (StatusCode::UNAUTHORIZED, "Invalid token").into_response(),
        },
        None => return (StatusCode::UNAUTHORIZED, "Missing token").into_response(),
    };

    let public_url = format!("/public/{}", file_id);
    let result = conn.lock().await.execute(
        "UPDATE files SET is_public = ?, public_url = ? WHERE id = ? AND user_id = ?",
        params![true, public_url, file_id.to_string(), user_id.to_string()],
    );

    match result {
        Ok(updated) if updated > 0 => {
            let file = conn.lock().await.query_row(
                "SELECT id, user_id, filename, file_path, is_public, public_url, created_at, updated_at FROM files WHERE id = ?",
                [file_id.to_string()],
                |row| {
                    Ok(File {
                        id: Uuid::parse_str(&row.get::<_, String>(0)?).unwrap(),
                        user_id: Uuid::parse_str(&row.get::<_, String>(1)?).unwrap(),
                        filename: row.get(2)?,
                        file_path: row.get(3)?,
                        is_public: row.get(4)?,
                        public_url: row.get(5)?,
                        created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?).unwrap().with_timezone(&Utc),
                        updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?).unwrap().with_timezone(&Utc),
                    })
                },
            ).unwrap();
            (StatusCode::OK, Json(file)).into_response()
        }
        _ => (StatusCode::NOT_FOUND, "File not found").into_response(),
    }
}

pub async fn serve_public_file(
    State(conn): State<DbConnection>,
    Path(file_id): Path<Uuid>,
) -> impl IntoResponse {
    let file_result = conn.lock().await.query_row(
        "SELECT file_path FROM files WHERE id = ? AND is_public = ?",
        params![file_id.to_string(), true],
        |row| row.get::<_, String>(0),
    );

    match file_result {
        Ok(file_path) => {
            let path = PathBuf::from(&file_path);
            match fs::File::open(&path).await {
                Ok(file) => {
                    let stream = ReaderStream::new(file);
                    let body = Body::from_stream(stream);

                    let mime_type = mime_guess::from_path(&path).first_or_octet_stream();

                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, mime_type.as_ref())
                        .header(header::CACHE_CONTROL, "public, max-age=31536000")
                        .body(body)
                        .unwrap()
                }
                Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
            }
        }
        Err(_) => (StatusCode::NOT_FOUND, "File not found").into_response(),
    }
}
