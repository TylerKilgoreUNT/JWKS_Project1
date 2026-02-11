use jwks_server_rust::keystore::KeyStore;

#[test]
fn jwks_contains_only_unexpired_keys() {
    let ks = KeyStore::new();
    let jwks = ks.jwks_unexpired();

    assert_eq!(jwks.keys.len(), 1, "Expected JWKS to include only the active key");

    assert_eq!(jwks.keys[0].kid, ks.active_kid());
}

#[test]
fn jwks_does_not_contain_expired_kid() {
    let ks = KeyStore::new();
    let jwks = ks.jwks_unexpired();

    assert!(
        jwks.keys.iter().all(|k| k.kid != ks.expired_kid()),
        "Expired key kid should not appear in JWKS"
    );
}

#[test]
fn jwk_has_required_rsa_fields() {
    let ks = KeyStore::new();
    let jwks = ks.jwks_unexpired();
    let k = &jwks.keys[0];

    assert_eq!(k.kty, "RSA");
    assert_eq!(k.use_, "sig");
    assert_eq!(k.alg, "RS256");

    assert!(!k.n.is_empty(), "n (modulus) should not be empty");
    assert!(!k.e.is_empty(), "e (exponent) should not be empty");
}