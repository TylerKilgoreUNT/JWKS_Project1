use std::sync::Arc;

use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum::extract::Query;
use std::collections::HashMap;

use crate::keystore::KeyStore;
use crate::jwk::Jwks;

pub async fn jwks_handler(State(ks): State<Arc<KeyStore>>) -> impl IntoResponse {
    let jwks: Jwks = ks.jwks_unexpired();
    (StatusCode::OK, Json(jwks))
}

pub async fn auth_handler(
    State(ks): State<Arc<KeyStore>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let use_expired = params.contains_key("expired");

    let rec = if use_expired { ks.expired_key() } else { ks.active_key() };

    match crate::jwt::issue_jwt_for_record(rec) {
        Ok(token) => (StatusCode::OK, Json(serde_json::json!({"token": token}))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e).into_response(),
    }
}
