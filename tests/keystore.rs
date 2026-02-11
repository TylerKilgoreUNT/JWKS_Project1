use jwks_server_rust::keystore::KeyStore;

#[test]
fn active_key_is_not_expired_and_expired_key_is_expired() {
    let ks = KeyStore::new();

    assert!(
        !ks.active_key().is_expired(),
        "Expected active key to be unexpired"
    );

    assert!(
        ks.expired_key().is_expired(),
        "Expected expired key to be expired"
    );
}

#[test]
fn kids_are_unique() {
    let ks = KeyStore::new();

    assert_ne!(
        ks.active_kid(),
        ks.expired_kid(),
        "Expected active and expired kids to be different"
    );
}

#[test]
fn unexpired_and_expired_key_lists_have_expected_sizes() {
    let ks = KeyStore::new();

    let unexpired = ks.unexpired_keys();
    let expired = ks.expired_keys();

    assert_eq!(unexpired.len(), 1, "Expected exactly 1 unexpired key");
    assert_eq!(expired.len(), 1, "Expected exactly 1 expired key");

    assert_eq!(unexpired[0].kid, ks.active_kid());
    assert_eq!(expired[0].kid, ks.expired_kid());
}
