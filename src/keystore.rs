use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::rand_core::OsRng; // IMPORTANT: use rsa's rand_core OsRng
use uuid::Uuid;
use time::OffsetDateTime;

use crate::jwk::{jwk_from_rsa_public, Jwks};

pub struct KeyRecord {
    pub kid: String,
    pub expires_at: i64,
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}

pub struct KeyStore {
    active: KeyRecord,
    expired: KeyRecord,
}

impl KeyStore {
    pub fn generate_key_record(expires_at: i64, key_bits: usize) -> KeyRecord {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, key_bits)
            .expect("RSA key generation failed");
        let public_key = RsaPublicKey::from(&private_key);
        let kid = Uuid::new_v4().to_string();

        KeyRecord {
            kid,
            expires_at,
            private_key,
            public_key,
        }
    }

    pub fn new() -> Self {
        Self::new_with_bits(2048)
    }

    pub fn new_with_bits(key_bits: usize) -> Self {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let active = Self::generate_key_record(now + 3600, key_bits);
        let expired = Self::generate_key_record(now - 3600, key_bits);

        Self { active, expired }
    }

    pub fn all_keys(&self) -> Vec<&KeyRecord> {
        vec![&self.active, &self.expired]
    }

    pub fn unexpired_keys(&self) -> Vec<&KeyRecord> {
        self.all_keys()
            .into_iter()
            .filter(|k| !k.is_expired())
            .collect()
    }

    pub fn expired_keys(&self) -> Vec<&KeyRecord> {
        self.all_keys()
            .into_iter()
            .filter(|k| k.is_expired())
            .collect()
    }

    pub fn active_key(&self) -> &KeyRecord {
        &self.active
    }

    pub fn expired_key(&self) -> &KeyRecord {
        &self.expired
    }

    pub fn active_kid(&self) -> &str {
        &self.active.kid
    }

    pub fn expired_kid(&self) -> &str {
        &self.expired.kid
    }

    pub fn jwks_unexpired(&self) -> Jwks {
        let keys = self
            .unexpired_keys()
            .into_iter()
            .map(|rec| jwk_from_rsa_public(&rec.public_key, &rec.kid))
            .collect();

        Jwks { keys }
    }
}

impl KeyRecord {
    fn now_unix() -> i64 {
        OffsetDateTime::now_utc().unix_timestamp()
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at <= Self::now_unix()
    }

    pub fn is_active(&self) -> bool {
        !self.is_expired()
    }
}