use std::net::TcpListener;
use std::sync::Arc;

use jwks_server_rust::app::{build_router, JWKS_PATH};
use jwks_server_rust::keystore::KeyStore;

use reqwest::Client;
use serde_json::Value;

async fn spawn_server() -> String {
    let keystore = Arc::new(KeyStore::new());
    let app = build_router(keystore);

    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind random port");
    let addr = listener.local_addr().unwrap();

    let tokio_listener = tokio::net::TcpListener::from_std(listener).unwrap();
    let server = axum::serve(tokio_listener, app);

    tokio::spawn(async move {
        if let Err(e) = server.await {
            eprintln!("server error: {e}");
        }
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn jwks_endpoint_returns_json_and_only_unexpired_keys() {
    let base = spawn_server().await;
    let client = Client::new();

    let resp = client
        .get(format!("{}{}", base, JWKS_PATH))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status().as_u16(), 200);

    let body: Value = resp.json().await.unwrap();
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