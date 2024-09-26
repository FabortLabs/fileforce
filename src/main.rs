mod auth;
mod db;
mod handlers;
mod models;

use axum::{
    routing::{get, post},
    Router,
};

#[tokio::main]
async fn main() {
    let conn = db::establish_connection().expect("Failed to establish database connection");

    let app = Router::new()
        .route("/register", post(handlers::register_user))
        .route("/login", post(handlers::login_user))
        .route("/upload", post(handlers::upload_file))
        .route("/files", get(handlers::get_user_files))
        .route("/files/:file_id/make_public", post(handlers::make_file_public))
        .route("/public/:file_id", get(handlers::serve_public_file))
        .with_state(conn);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}