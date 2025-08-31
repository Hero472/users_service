use std::error::Error;
use serde::{Serialize, Deserialize};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use base64::Engine;
use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, KeyInit, Nonce};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use chrono::{Utc, Duration};
use crate::utils::{config::AppConfig, jwt::Claims};
use bcrypt::{hash as crypt_hash, DEFAULT_COST};

fn derive_key_from_string(key_str: &str) -> [u8; 32] {
    let hasher = Sha256::new_with_prefix(key_str.as_bytes());
    hasher.finalize().into()
}

#[derive(Serialize, Deserialize)]
pub struct AuthUtils;

impl AuthUtils {

    pub fn hash(input: &str) -> Result<String, bcrypt::BcryptError> {
        crypt_hash(input, DEFAULT_COST)
    }

    pub fn verify_hash(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(password, hash)
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

    pub fn encrypt(input: &str) -> Result<String, Box<dyn Error>> {
        
        let config = AppConfig::global();

        let key_bytes = derive_key_from_string(&config.encryption_key);
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let cipher_text = cipher.encrypt(&nonce, input.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        let mut encrypted_data = nonce.to_vec();
        encrypted_data.extend_from_slice(&cipher_text);

        Ok(base64::engine::general_purpose::STANDARD.encode(encrypted_data))
    }

    pub fn decrypt(input: &str) -> Result<String, Box<dyn Error>> {

        let config = AppConfig::global();

        let key_bytes = derive_key_from_string(&config.encryption_key);
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);

        let encrypted_data = base64::engine::general_purpose::STANDARD.decode(input)
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

// ---------------------------------------- TESTS ----------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    impl AppConfig {
        pub fn test_config() -> AppConfig {
            AppConfig {
                secret_key: "test_secret_key_for_jwt_signing_operations".to_string(),
                encryption_key: "test_encryption_key_for_aes_operations".to_string(),
                database_url: "key".to_string(),
                smtp_server: "key".to_string(),
                smtp_username: "key".to_string(),
                smtp_password: "key".to_string(),
                email_user: "key".to_string(),
                email_password: "key".to_string(),
                email_host: "key".to_string(),
                email_port: "key".to_string(),
            }
        }
    }

    #[test]
    fn test_hash() {
        let input = "test_password";
        let hash1 = AuthUtils::hash(input).unwrap();
        let hash2 = AuthUtils::hash(input).unwrap();
        
        assert_eq!(hash1, hash2);
        
        // Hash should be 32 bytes (SHA256)
        assert_eq!(hash1.len(), 64);
        
        let different_hash = AuthUtils::hash("different_password").unwrap();
        assert_ne!(hash1, different_hash);
    }

    #[test]
    fn test_verify_hash() {
        let input = "test_password";
        let hash = AuthUtils::hash(input).unwrap();
        
        assert!(AuthUtils::verify_hash(input, &hash).unwrap());
        
        assert!(!AuthUtils::verify_hash("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_generate_token() {
        let email = "test@example.com";
        let minutes = 60;
        
        let token = AuthUtils::generate_token(email, minutes);
        
        assert!(!token.is_empty());
        
        // Token should contain 3 parts separated by dots (JWT format)
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        
        // Each part should be valid base64url (approximately)
        for part in parts {
            assert!(!part.is_empty());
        }
    }

    #[test]
    fn test_verify_token_valid() {
        let email = "test@example.com";
        let minutes = 60;
        
        let token = AuthUtils::generate_token(email, minutes);
        
        // Should verify valid token
        assert!(AuthUtils::verify_token(&token));
    }

    #[test]
    fn test_verify_token_invalid() {
        // Should reject completely invalid token
        assert!(!AuthUtils::verify_token("invalid.token.here"));
        
        // Should reject empty token
        assert!(!AuthUtils::verify_token(""));
        
        // Should reject malformed token
        assert!(!AuthUtils::verify_token("not.a.valid.jwt.token"));
    }

    #[test]
    fn test_is_token_expired_valid() {
        let email = "test@example.com";
        let minutes = 60;
        
        let token = AuthUtils::generate_token(email, minutes);
        
        assert!(!AuthUtils::is_token_expired(&token));
    }

    #[test]
    fn test_is_token_expired_expired() {
        let email = "test@example.com";
        let minutes = -1; // Already expired
        
        let token = AuthUtils::generate_token(email, minutes);
        
        // Expired token should be detected as expired
        assert!(AuthUtils::is_token_expired(&token));
    }

    #[test]
    fn test_is_token_expired_invalid() {
        // Invalid token should be treated as expired
        assert!(AuthUtils::is_token_expired("invalid.token.here"));
        assert!(AuthUtils::is_token_expired(""));
    }

    #[test]
    fn test_encrypt_decrypt() {
        let email = "test@example.com";
        
        // Test encryption
        let encrypted = AuthUtils::encrypt(email).expect("Encryption should succeed");
        
        // Encrypted data should not be empty
        assert!(!encrypted.is_empty());
        
        // Encrypted data should be different from original
        assert_ne!(encrypted, email);
        
        // Test decryption
        let decrypted = AuthUtils::decrypt(&encrypted).expect("Decryption should succeed");
        
        // Decrypted data should match original
        assert_eq!(decrypted, email);
    }

    #[test]
    fn test_encrypt_different_outputs() {
        let email = "test@example.com";
        
        // Multiple encryptions of same data should produce different results (due to random nonce)
        let encrypted1 = AuthUtils::encrypt(email).expect("Encryption should succeed");
        let encrypted2 = AuthUtils::encrypt(email).expect("Encryption should succeed");
        
        assert_ne!(encrypted1, encrypted2);
        
        // But both should decrypt to the same original value
        let decrypted1 = AuthUtils::decrypt(&encrypted1).expect("Decryption should succeed");
        let decrypted2 = AuthUtils::decrypt(&encrypted2).expect("Decryption should succeed");
        
        assert_eq!(decrypted1, email);
        assert_eq!(decrypted2, email);
        assert_eq!(decrypted1, decrypted2);
    }

    #[test]
    fn test_decrypt_invalid_data() {
        // Test with invalid base64
        let result = AuthUtils::decrypt("not_valid_base64!");
        assert!(result.is_err());
        
        // Test with too short data
        let short_data = base64::engine::general_purpose::STANDARD.encode(&[1, 2, 3]);
        let result = AuthUtils::decrypt(&short_data);
        assert!(result.is_err());
        
        // Test with corrupted data
        let corrupted = base64::engine::general_purpose::STANDARD.encode(&[0u8; 50]);
        let result = AuthUtils::decrypt(&corrupted);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_string() {
        let empty = "";
        
        let encrypted = AuthUtils::encrypt(empty).expect("Should encrypt empty string");
        let decrypted = AuthUtils::decrypt(&encrypted).expect("Should decrypt empty string");
        
        assert_eq!(decrypted, empty);
    }

    #[test]
    fn test_encrypt_unicode() {
        let unicode_email = "测试@例子.com";
        
        let encrypted = AuthUtils::encrypt(unicode_email).expect("Should encrypt unicode");
        let decrypted = AuthUtils::decrypt(&encrypted).expect("Should decrypt unicode");
        
        assert_eq!(decrypted, unicode_email);
    }

    #[test]
    fn test_derive_key_from_string_consistency() {
        let key_str = "test_key";
        
        let key1 = derive_key_from_string(key_str);
        let key2 = derive_key_from_string(key_str);
        
        // Same input should produce same key
        assert_eq!(key1, key2);
        
        // Key should be 32 bytes
        assert_eq!(key1.len(), 32);
        
        // Different input should produce different key
        let different_key = derive_key_from_string("different_key");
        assert_ne!(key1, different_key);
    }

    #[test]
    fn test_full_auth_workflow() {
        let email = "integration@test.com";
        let password = "secure_password_123";
        
        // Hash password
        let password_hash = AuthUtils::hash(password).unwrap();
        assert!(AuthUtils::verify_hash(password, &password_hash).unwrap());
        
        // Encrypt email
        let encrypted_email = AuthUtils::encrypt(email).expect("Encryption should work");
        let decrypted_email = AuthUtils::decrypt(&encrypted_email).expect("Decryption should work");
        assert_eq!(decrypted_email, email);
        
        // Generate and verify token
        let token = AuthUtils::generate_token(email, 60);
        assert!(AuthUtils::verify_token(&token));
        assert!(!AuthUtils::is_token_expired(&token));
    }
}