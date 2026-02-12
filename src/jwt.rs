use serde::Serialize;
use jsonwebtoken::{EncodingKey, Header, Algorithm};
use time::OffsetDateTime;
use rsa::pkcs1::EncodeRsaPrivateKey;

use crate::keystore::KeyRecord;

#[derive(Serialize)]
struct Claims {
	sub: String,
	iat: i64,
	exp: i64,
}

pub fn issue_jwt_for_record(rec: &KeyRecord) -> Result<String, String> {
	let iat = OffsetDateTime::now_utc().unix_timestamp();
	let exp = rec.expires_at;

	let claims = Claims {
		sub: "user".to_string(),
		iat,
		exp,
	};

	// Build header with kid
	let mut header = Header::new(Algorithm::RS256);
	header.kid = Some(rec.kid.clone());

	// Convert private key to PKCS1 PEM and create encoding key
	let pem = rec
		.private_key
		.to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
		.map_err(|e| format!("PEM conversion failed: {}", e))?;

	let encoding_key = EncodingKey::from_rsa_pem(pem.as_bytes())
		.map_err(|e| format!("EncodingKey creation failed: {}", e))?;

	jsonwebtoken::encode(&header, &claims, &encoding_key).map_err(|e| e.to_string())
}
