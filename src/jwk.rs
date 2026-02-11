use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPublicKey};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,

    #[serde(rename = "use")]
    pub use_: String,

    pub alg: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

fn b64url_biguint(value: &BigUint) -> String {
    URL_SAFE_NO_PAD.encode(value.to_bytes_be())
}

pub fn jwk_from_rsa_public(pubkey: &RsaPublicKey, kid: &str) -> Jwk {
    let n = b64url_biguint(pubkey.n());
    let e = b64url_biguint(pubkey.e());

    Jwk {
        kty: "RSA".to_string(),
        kid: kid.to_string(),
        use_: "sig".to_string(),
        alg: "RS256".to_string(),
        n,
        e,
    }
}