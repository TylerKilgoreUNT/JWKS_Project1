use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

use crate::keystore::KeyStore;
use crate::jwk::Jwks;

pub async fn jwks_handler(State(ks): State<Arc<KeyStore>>) -> impl IntoResponse {
    let jwks: Jwks = ks.jwks_unexpired();
    (StatusCode::OK, Json(jwks))
}
