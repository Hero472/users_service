use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use base64::Engine;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use chrono::{Utc, Duration};
use crate::utils::jwt::Claims;

const SECRET_KEY: &str = "your_secret_key";

#[derive(Serialize, Deserialize)]
pub struct AuthUtils;

impl AuthUtils {

    pub fn hash(input: &str) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn verify_hash(input: &str, expected_hash: &[u8]) -> bool {
        let hash = Self::hash(input);
        hash == expected_hash
    }

    pub fn base64_encode(input: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(input)
    }

    pub fn check_2_base64(input: &str, expected: &str) -> bool {
        let encoded_input = Self::base64_encode(input);
        encoded_input == expected
    }

    pub fn generate_token(email: &str, minutes: i64) -> String {
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(minutes))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: email.to_owned(),
            exp: expiration,
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(SECRET_KEY.as_ref()),
        ).unwrap()
    }

    pub fn verify_token(token: &str) -> bool {
        let validation = Validation::default();
        let result = decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET_KEY.as_ref()),
            &validation,
        );
        result.is_ok()
    }

    pub fn is_token_expired(token: &str) -> bool {
        let validation = Validation::default();
        if let Ok(data) = decode::<Claims>(
            token,
            &DecodingKey::from_secret(SECRET_KEY.as_ref()),
            &validation,
        ) {
            let now = Utc::now().timestamp() as usize;
            data.claims.exp < now
        } else {
            true // Treat invalid token as expired
        }
    }

}