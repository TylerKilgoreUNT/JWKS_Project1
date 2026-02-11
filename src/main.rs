use std::sync::Arc;

use jwks_server_rust::app::build_router;
use jwks_server_rust::keystore::KeyStore;

#[tokio::main]
async fn main() {
    let keystore = Arc::new(KeyStore::new());
    let app = build_router(keystore);

    let addr = "127.0.0.1:3000";
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind address");

    println!("JWKS server listening on http://{}", addr);

    axum::serve(listener, app)
        .await
        .expect("server failed");
}