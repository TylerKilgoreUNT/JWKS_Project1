use std::sync::Arc;
use axum::{routing::{get, post}, Router};
use crate::{keystore::KeyStore, routes};

pub const JWKS_PATH: &str = "/.well-known/jwks.json";
pub const AUTH_PATH: &str = "/auth";

pub fn build_router(keystore: Arc<KeyStore>) -> Router {
    Router::new()
        .route(JWKS_PATH, get(routes::jwks_handler))
        .route(AUTH_PATH, post(routes::auth_handler))
        .with_state(keystore)
}