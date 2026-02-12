use std::sync::{Arc, OnceLock};

use jwks_server_rust::app::{build_router, JWKS_PATH};
use jwks_server_rust::keystore::KeyStore;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;
use serde_json::Value;

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

#[tokio::test]
async fn jwks_endpoint_returns_json_and_only_unexpired_keys() {
    let (status, body, body_text) = request_json("GET", JWKS_PATH).await;
    assert_eq!(status, StatusCode::OK, "status: {status}, body: {body_text}");

    let keys = body["keys"].as_array().expect("JWKS should have a keys array");

    assert_eq!(keys.len(), 1);

    let k = &keys[0];
    assert_eq!(k["kty"], "RSA");
    assert_eq!(k["use"], "sig");
    assert_eq!(k["alg"], "RS256");

    assert!(k["kid"].as_str().unwrap().len() > 0);
    assert!(k["n"].as_str().unwrap().len() > 0);
    assert!(k["e"].as_str().unwrap().len() > 0);
}

#[tokio::test]
async fn jwks_rejects_wrong_method() {
    let app = build_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(JWKS_PATH)
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
}