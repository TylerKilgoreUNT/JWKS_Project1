use std::sync::Arc;
use axum::{routing::get, Router};
use crate::{keystore::KeyStore, routes};

pub const JWKS_PATH: &str = "/.well-known/jwks.json";

pub fn build_router(keystore: Arc<KeyStore>) -> Router {
    Router::new()
        .route(JWKS_PATH, get(routes::jwks_handler))
        .with_state(keystore)
}