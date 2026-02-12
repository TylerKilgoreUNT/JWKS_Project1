use std::sync::{Arc, OnceLock};

use jwks_server_rust::app::{build_router, AUTH_PATH, JWKS_PATH};
use jwks_server_rust::keystore::KeyStore;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use serde_json::Value;
use base64::Engine;
use time::OffsetDateTime;
use jsonwebtoken::{DecodingKey, Validation, Algorithm, decode};

fn build_test_app() -> axum::Router {
    static TEST_KEYSTORE: OnceLock<Arc<KeyStore>> = OnceLock::new();
    let keystore = TEST_KEYSTORE
        .get_or_init(|| Arc::new(KeyStore::new_with_bits(2048)))
        .clone();
    build_router(keystore)
}

async fn request_json(method: &str, uri: &str) -> (StatusCode, Value, String) {
    let app = build_test_app();
    let response = app
        .oneshot(
            Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    let status = response.status();
    let body_bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();

    let body_text = String::from_utf8_lossy(&body_bytes).to_string();
    if body_text.trim().is_empty() {
        return (status, Value::Null, body_text);
    }

    let value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => Value::Null,
    };

    (status, value, body_text)
}

fn decode_jwt_parts(token: &str) -> (Value, Value) {
    let parts: Vec<&str> = token.split('.').collect();
    assert!(parts.len() == 3, "token should have 3 parts");

    let header_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("header base64 decode");
    let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload base64 decode");

    let header: Value = serde_json::from_slice(&header_json).expect("parse header json");
    let payload: Value = serde_json::from_slice(&payload_json).expect("parse payload json");

    (header, payload)
}

#[tokio::test]
async fn auth_returns_jwt_with_kid_header() {
    let (status, body, body_text) = request_json("POST", AUTH_PATH).await;
    assert_eq!(status, StatusCode::OK, "status: {status}, body: {body_text}");
    let token = body["token"].as_str().expect("token should be a string");

    let (header, payload) = decode_jwt_parts(token);

    let kid = header["kid"].as_str().expect("kid should exist");
    assert!(kid.len() > 0);

    let (jwks_status, jwks, jwks_text) = request_json("GET", JWKS_PATH).await;
    assert_eq!(jwks_status, StatusCode::OK, "status: {jwks_status}, body: {jwks_text}");
    let keys = jwks["keys"].as_array().expect("jwks keys array");
    let jwk = keys.iter().find(|k| k["kid"] == kid).expect("kid in jwks");

    let n = jwk["n"].as_str().expect("n present");
    let e = jwk["e"].as_str().expect("e present");

    let decoding_key = DecodingKey::from_rsa_components(n, e).expect("decoding key");
    let validation = Validation::new(Algorithm::RS256);

    let data = decode::<Value>(token, &decoding_key, &validation).expect("valid jwt");
    let exp = data.claims["exp"].as_i64().expect("exp claim");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(exp > now, "exp should be in the future");
    assert_eq!(payload["sub"].as_str().unwrap(), "user");
}

#[tokio::test]
async fn auth_with_expired_param_uses_expired_kid() {
    let (status, body, body_text) = request_json("POST", "/auth?expired").await;
    assert_eq!(status, StatusCode::OK, "status: {status}, body: {body_text}");
    let token = body["token"].as_str().expect("token should be a string");

    let (header, payload) = decode_jwt_parts(token);
    let kid = header["kid"].as_str().expect("kid should exist");
    assert!(kid.len() > 0);

    let (jwks_status, jwks, jwks_text) = request_json("GET", JWKS_PATH).await;
    assert_eq!(jwks_status, StatusCode::OK, "status: {jwks_status}, body: {jwks_text}");
    let keys = jwks["keys"].as_array().expect("jwks keys array");
    assert!(keys.iter().all(|k| k["kid"] != kid), "expired kid should not be in jwks");

    let exp = payload["exp"].as_i64().expect("exp claim");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    assert!(exp < now, "expired token exp should be in the past");
}

#[tokio::test]
async fn auth_rejects_wrong_method() {
    let app = build_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(AUTH_PATH)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}
