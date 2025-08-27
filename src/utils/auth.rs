use std::error::Error;
use serde::{Serialize, Deserialize};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use base64::Engine;
use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, KeyInit, Nonce};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use chrono::{Utc, Duration};
use crate::utils::{config::AppConfig, jwt::Claims};

fn derive_key_from_string(key_str: &str) -> [u8; 32] {
    let hasher = Sha256::new_with_prefix(key_str.as_bytes());
    hasher.finalize().into()
}

#[derive(Serialize, Deserialize)]
pub struct AuthUtils;

impl AuthUtils {

    pub fn hash(input: &str) -> Vec<u8> {
        let mut hasher = Sha256::new_with_prefix(input.as_bytes());
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

        let config = AppConfig::global();

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
            &EncodingKey::from_secret(config.secret_key.as_ref()),
        ).unwrap()
    }

    pub fn verify_token(token: &str) -> bool {
        let config = AppConfig::global();

        let validation = Validation::default();
        let result = decode::<Claims>(
            token,
            &DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        );
        result.is_ok()
    }

    pub fn is_token_expired(token: &str) -> bool {
        let config = AppConfig::global();

        let validation = Validation::default();
        if let Ok(data) = decode::<Claims>(
            token,
            &DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ) {
            let now = Utc::now().timestamp() as usize;
            data.claims.exp < now
        } else {
            true // Treat invalid token as expired
        }
    }

    pub fn encrypt(email: &str) -> Result<String, Box<dyn Error>> {
        
        let config = AppConfig::global();

        let key_bytes = derive_key_from_string(&config.encryption_key);
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let cipher_text = cipher.encrypt(&nonce, email.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&cipher_text);

        Ok(base64::engine::general_purpose::STANDARD.encode(encrypted_data))
    }


    pub fn decrypt(encrypted_email: &str) -> Result<String, Box<dyn Error>> {

        let config = AppConfig::global();

        let key_bytes = derive_key_from_string(&config.encryption_key);
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let encrypted_data = base64::engine::general_purpose::STANDARD.decode(encrypted_email)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;

        if encrypted_data.len() < 12 {
            return Err("Invalid encrypted data: too short".into());
        }
        
        let (nonce_bytes, cipher_text) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, cipher_text)
            .map_err(|e| format!("Decryption failed: {}", e))?;
        
        String::from_utf8(plaintext)
            .map_err(|e| format!("Invalid UTF-8: {}", e).into())
    }
}