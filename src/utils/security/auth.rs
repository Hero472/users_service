use std::error::Error;
use mongodb::bson::Uuid;
use serde::{Serialize, Deserialize};
use sha2::{digest::generic_array::GenericArray, Digest, Sha256};
use base64::Engine;
use aes_gcm::{aead::{Aead, OsRng}, AeadCore, Aes256Gcm, KeyInit, Nonce};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use chrono::{Utc, Duration};
use crate::{domain::UserRole, utils::{config::AppConfig, security::jwt::{AccessData, Claims, RefreshData}}};
use bcrypt::{hash as crypt_hash, DEFAULT_COST};

fn derive_key_from_string(key_str: &str) -> [u8; 32] {
    let hasher = Sha256::new_with_prefix(key_str.as_bytes());
    hasher.finalize().into()
}

#[derive(Serialize, Deserialize)]
pub struct AuthUtils;

impl AuthUtils {

    pub fn hash(input: &str) -> Result<String, Box<dyn Error>> {
        let mut hasher = Sha256::new_with_prefix(input.as_bytes());
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    pub fn hash_password(input: &str) -> Result<String, bcrypt::BcryptError> {
        crypt_hash(input, DEFAULT_COST)
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(password, hash)
    }

    pub fn generate_access_token(email: &str, role: UserRole) -> String {
        let config = AppConfig::global();

        let now = Utc::now();
        let expiration = now
            .checked_add_signed(Duration::minutes(15))
            .expect("valid timestamp")
            .timestamp() as u64;

        let claims = Claims {
            sub: email.to_owned(),
            exp: expiration,
            iat: now.timestamp() as u64,
            data: AccessData {
                email: email.to_string(),
                role: role,
            },
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret_key.as_ref()),
        ).expect("failed to sign access token")
    }

    pub fn generate_refresh_token(email: &str) -> String {
        let config = AppConfig::global();

        let now = Utc::now();
        let expiration = now
            .checked_add_signed(Duration::days(30)) // 30 days validity
            .expect("valid timestamp")
            .timestamp() as u64;

        let claims = Claims {
            sub: email.to_owned(),
            exp: expiration,
            iat: now.timestamp() as u64,
            data: RefreshData {
                jti: Uuid::new().to_string(),
            },
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret_key.as_ref()),
        ).expect("failed to sign refresh token")
    }

    pub fn verify_token<T>(token: &str) -> bool
    where
        T: for<'de> Deserialize<'de> 
    {
        let config = AppConfig::global();

        let validation = Validation::default();
        let result = decode::<Claims<T>>(
            token,
            &DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        );
        result.is_ok()
    }

    pub fn is_token_expired<T>(token: &str) -> bool 
    where
        T: for<'de> Deserialize<'de>
    {
        let config = AppConfig::global();

        let validation = Validation::default();
        if let Ok(data) = decode::<Claims<T>>(
            token,
            &DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ) {
            let now = Utc::now().timestamp() as u64;
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
        let hash1 = AuthUtils::hash("hash1").unwrap();
        let hash2 = AuthUtils::hash("hash2").unwrap();
        
        assert!(!hash1.is_empty());
        assert!(!hash2.is_empty());
        
        assert_ne!(hash1, hash2, "Different inputs should produce different hashes");
        
        let hash1_again = AuthUtils::hash("hash1").unwrap();
        assert_eq!(hash1, hash1_again, "Same input should produce same hash");
        
        assert_eq!(hash1.len(), 64, "SHA-256 hash should be 64 hex characters");
        assert_eq!(hash2.len(), 64, "SHA-256 hash should be 64 hex characters");
        
        assert!(hex::decode(&hash1).is_ok(), "Hash should be valid hex string");
        assert!(hex::decode(&hash2).is_ok(), "Hash should be valid hex string");
    }

    #[test]
    fn test_hash_edge_cases() {
        let empty_hash = AuthUtils::hash("").unwrap();
        assert!(!empty_hash.is_empty());
        assert_eq!(empty_hash.len(), 64);
        
        let long_string = "a".repeat(1000);
        let long_hash = AuthUtils::hash(&long_string).unwrap();
        assert_eq!(long_hash.len(), 64);
        
        let special_hash = AuthUtils::hash("!@#$%^&*()").unwrap();
        assert_eq!(special_hash.len(), 64);
        
        let unicode_hash = AuthUtils::hash("hello 世界 🌍").unwrap();
        assert_eq!(unicode_hash.len(), 64);
    }

    #[test]
    fn test_hash_deterministic() {
        let input = "consistent_input";
        
        let hash1 = AuthUtils::hash(input).unwrap();
        let hash2 = AuthUtils::hash(input).unwrap();
        let hash3 = AuthUtils::hash(input).unwrap();
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
        assert_eq!(hash1, hash3);
    }

    #[test]
    fn test_hash_password() {
        let password = "my_secure_password";
        let hash = AuthUtils::hash_password(password).unwrap();
        
        assert!(!hash.is_empty());
        
        assert!(hash.starts_with("$2b$") || hash.starts_with("$2a$") || hash.starts_with("$2y$"));
        
        let parts: Vec<&str> = hash.split('$').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[1], "2b");
        assert_eq!(parts[2].len(), 2);
    }

    #[test]
    fn test_verify_password_correct() {
        let password = "correct_password";
        let hash = AuthUtils::hash_password(password).unwrap();
        
        let verification = AuthUtils::verify_password(password, &hash).unwrap();
        assert!(verification, "Correct password should verify successfully");
    }

    #[test]
    fn test_verify_password_incorrect() {
        let password = "correct_password";
        let hash = AuthUtils::hash_password(password).unwrap();
        
        let verification = AuthUtils::verify_password("wrong_password", &hash).unwrap();
        assert!(!verification, "Wrong password should fail verification");
    }

    #[test]
    fn test_verify_password_different_case() {
        let password = "Password123";
        let hash = AuthUtils::hash_password(password).unwrap();
        
        let verification_lower = AuthUtils::verify_password("password123", &hash).unwrap();
        assert!(!verification_lower, "Different case should fail");
        
        let verification_upper = AuthUtils::verify_password("PASSWORD123", &hash).unwrap();
        assert!(!verification_upper, "Different case should fail");
    }

    #[test]
    fn test_hash_verify_round_trip() {
        let test_passwords = vec![
            "simple",
            "password with spaces",
            "special!@#$%^&*()",
            "very_long_password_that_is_quite_lengthy_and_contains_many_characters",
            "unicode_世界_🌍",
            "123456",
            "",
        ];
        
        for password in test_passwords {
            let hash = AuthUtils::hash_password(password)
                .unwrap_or_else(|_| panic!("Failed to hash password: {}", password));
            
            let verification = AuthUtils::verify_password(password, &hash)
                .unwrap_or_else(|_| panic!("Failed to verify password: {}", password));
            
            assert!(
                verification,
                "Password '{}' should verify against its own hash",
                password
            );
        }
    }

    #[test]
    fn test_different_passwords_produce_different_hashes() {
        let password1 = "password1";
        let password2 = "password2";
        
        let hash1 = AuthUtils::hash_password(password1).unwrap();
        let hash2 = AuthUtils::hash_password(password2).unwrap();
        
        assert_ne!(
            hash1, hash2,
            "Different passwords should produce different hashes"
        );
    }

    #[test]
    fn test_same_password_produces_different_hashes() {
        let password = "same_password";
        
        let hash1 = AuthUtils::hash_password(password).unwrap();
        let hash2 = AuthUtils::hash_password(password).unwrap();
        let hash3 = AuthUtils::hash_password(password).unwrap();
        
        assert_ne!(hash1, hash2, "Same password should have different hashes (salt)");
        assert_ne!(hash1, hash3, "Same password should have different hashes (salt)");
        assert_ne!(hash2, hash3, "Same password should have different hashes (salt)");

        assert!(AuthUtils::verify_password(password, &hash1).unwrap());
        assert!(AuthUtils::verify_password(password, &hash2).unwrap());
        assert!(AuthUtils::verify_password(password, &hash3).unwrap());
    }

    #[test]
    fn test_verify_with_invalid_hash() {
        let result = AuthUtils::verify_password("password", "not_a_valid_bcrypt_hash");
        assert!(result.is_err(), "Invalid hash should return error");
        
        let result = AuthUtils::verify_password("password", "$2b$12$tooshort");
        assert!(result.is_err(), "Malformed hash should return error");
    }

    #[test]
    fn test_password_whitespace_sensitive() {
        let password = "password";
        let hash = AuthUtils::hash_password(password).unwrap();
        
        let verification_leading_space = AuthUtils::verify_password(" password", &hash).unwrap();
        assert!(!verification_leading_space, "Leading space should fail");
        
        let verification_trailing_space = AuthUtils::verify_password("password ", &hash).unwrap();
        assert!(!verification_trailing_space, "Trailing space should fail");
        
        let verification_both_spaces = AuthUtils::verify_password(" password ", &hash).unwrap();
        assert!(!verification_both_spaces, "Both spaces should fail");
    }

    #[test]
    fn test_null_bytes_in_password() {
        let password = "pass\0word";
        let hash = AuthUtils::hash_password(password).unwrap();
        
        let verification = AuthUtils::verify_password(password, &hash).unwrap();
        assert!(verification, "Null bytes should work if consistent");
        
        let verification_wrong = AuthUtils::verify_password("password", &hash).unwrap();
        assert!(!verification_wrong, "Missing null byte should fail");
    }

    #[test]
    fn test_hash_performance() {  
        use std::time::Instant;
        
        let password = "performance_test_password";
        let start = Instant::now();
        
        let hash = AuthUtils::hash_password(password).unwrap();
        let elapsed = start.elapsed();
        
        assert!(elapsed.as_millis() > 0, "Bcrypt should take measurable time");
        assert!(AuthUtils::verify_password(password, &hash).unwrap());
    }

    #[test]
    fn test_generate_access_token() {
        let email = "test@example.com";
        let role = UserRole::User;
        
        let token = AuthUtils::generate_access_token(email, role.clone());
        
        assert!(!token.is_empty());
        
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
        
        let config = AppConfig::global();
        let validation = Validation::default();
        
        let token_data = decode::<Claims<AccessData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ).expect("Should decode valid token");
        
        assert_eq!(token_data.claims.sub, email);
        assert_eq!(token_data.claims.data.email, email);
        assert_eq!(token_data.claims.data.role, role);
    }

    #[test]
    fn test_generate_refresh_token() {
        let email = "user@example.com";
        
        let token = AuthUtils::generate_refresh_token(email);
        
        assert!(!token.is_empty());
        
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have 3 parts");
        
        let config = AppConfig::global();
        let validation = Validation::default();
        
        let token_data = decode::<Claims<RefreshData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ).expect("Should decode valid refresh token");
        
        assert_eq!(token_data.claims.sub, email);
        assert!(!token_data.claims.data.jti.is_empty());
    }

    #[test]
    fn test_access_token_expiration() { 
        let email = "test@example.com";
        let role = UserRole::User;
        
        let token = AuthUtils::generate_access_token(email, role);
        
        let config = AppConfig::global();
        let mut validation = Validation::default();
        validation.validate_exp = true;
        
        let token_data = decode::<Claims<AccessData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ).expect("Should decode fresh token");
        
        let now = Utc::now().timestamp() as u64;
        assert!(
            token_data.claims.exp > now,
            "Access token should not be expired immediately"
        );
        
        let expected_exp = now + (15 * 60);
        let diff = (token_data.claims.exp as i64 - expected_exp as i64).abs();
        assert!(
            diff <= 2, // Allow 2 seconds difference for test execution time
            "Access token expiration should be ~15 minutes from now"
        );
    }

    #[test]
    fn test_refresh_token_expiration() {
        let email = "test@example.com";
        
        let token = AuthUtils::generate_refresh_token(email);
        
        let config = AppConfig::global();
        let mut validation = Validation::default();
        validation.validate_exp = true;
        
        let token_data = decode::<Claims<RefreshData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ).expect("Should decode fresh refresh token");
        

        let now = Utc::now().timestamp() as u64;
        let expected_exp = now + (30 * 24 * 60 * 60);
        let diff = (token_data.claims.exp as i64 - expected_exp as i64).abs();
        assert!(
            diff <= 2,
            "Refresh token expiration should be ~30 days from now"
        );
    }

    #[test]
    fn test_different_emails_produce_different_tokens() { 
        let token1 = AuthUtils::generate_access_token("user1@example.com", UserRole::User);
        let token2 = AuthUtils::generate_access_token("user2@example.com", UserRole::User);
        
        assert_ne!(
            token1, token2,
            "Different emails should produce different tokens"
        );
    }

    #[test]
    fn test_refresh_token_has_jti() {
        let email = "jti_test@example.com";
        let token = AuthUtils::generate_refresh_token(email);
        
        let config = AppConfig::global();
        let decoded = decode::<Claims<RefreshData>>(
            &token,
            &DecodingKey::from_secret(config.secret_key.as_ref()),
            &Validation::default(),
        ).unwrap();
    
        let jti = &decoded.claims.data.jti;
        assert!(!jti.is_empty());
        assert!(Uuid::parse_str(jti).is_ok());
        
    }

    #[test]
    fn test_different_roles_produce_different_tokens() {
        let token1 = AuthUtils::generate_access_token("user@example.com", UserRole::Admin);
        let token2 = AuthUtils::generate_access_token("user@example.com", UserRole::User);
        
        assert_ne!(
            token1, token2,
            "Different roles should produce different tokens"
        );
    }

    #[test]
    fn test_empty_email() {
        let token = AuthUtils::generate_access_token("", UserRole::User);
        
        let config = AppConfig::global();
        let validation = Validation::default();
        
        let token_data = decode::<Claims<AccessData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ).expect("Should handle empty strings");
        
        assert_eq!(token_data.claims.sub, "");
        assert_eq!(token_data.claims.data.email, "");
    }

    #[test]
    fn test_special_characters_in_email() {
        let email = "user+filter@example.com";
        
        let token = AuthUtils::generate_access_token(email, UserRole::User);
        
        let config = AppConfig::global();
        let validation = Validation::default();
        
        let token_data = decode::<Claims<AccessData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(config.secret_key.as_ref()),
            &validation,
        ).expect("Should handle special characters");
        
        assert_eq!(token_data.claims.sub, email);
        assert_eq!(token_data.claims.data.email, email);
    }

    #[test]
    fn test_token_with_wrong_secret_fails() {
        let email = "test@example.com";
        
        let token = AuthUtils::generate_access_token(email, UserRole::User);
        
        let wrong_validation = Validation::default();
        let wrong_secret = "wrong_secret_key_that_is_different_from_app_secret";
        
        let result = decode::<Claims<AccessData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_secret(wrong_secret.as_ref()),
            &wrong_validation,
        );
        
        assert!(
            result.is_err(),
            "Token should fail to decode with wrong secret"
        );
    }

    #[test]
    fn test_verify_token_valid() { 
        let email = "verify@test.com";
        
        let access_token = AuthUtils::generate_access_token(email, UserRole::User);
        let refresh_token = AuthUtils::generate_refresh_token(email);
        
        assert!(AuthUtils::verify_token::<AccessData>(&access_token));
        assert!(AuthUtils::verify_token::<RefreshData>(&refresh_token));
    }

    #[test]
    fn test_verify_token_invalid() {
        assert!(!AuthUtils::verify_token::<AccessData>("invalid.token.here"));
        assert!(!AuthUtils::verify_token::<AccessData>(""));
    }

    #[test]
    fn test_is_token_expired_fresh_token() {
        let token = AuthUtils::generate_access_token("fresh@test.com", UserRole::User);
        
        assert!(!AuthUtils::is_token_expired::<AccessData>(&token));
    }

    #[test]
    fn test_is_token_expired_invalid_token() {
        assert!(AuthUtils::is_token_expired::<AccessData>("invalid.token.here"));
        assert!(AuthUtils::is_token_expired::<AccessData>(""));
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let plaintext = "Hello, World!";
        
        let encrypted = AuthUtils::encrypt(plaintext).unwrap();
        let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
        assert_ne!(encrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let plaintext = "";
        
        let encrypted = AuthUtils::encrypt(plaintext).unwrap();
        let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_long_text() {
        let plaintext = "This is a very long text that should be properly encrypted and decrypted without any issues. It contains multiple sentences and should test the encryption algorithm's handling of larger inputs.";
        
        let encrypted = AuthUtils::encrypt(plaintext).unwrap();
        let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_special_characters() {
        let test_cases = vec![
            "Special chars: !@#$%^&*()",
            "Unicode: 中文 Español Français",
            "Emoji: 🚀 🌍 💻",
            "Mixed: Hello 世界! @#$% 🎉",
            "Newlines: Line1\nLine2\nLine3",
            "Tabs: Col1\tCol2\tCol3",
        ];
        
        for plaintext in test_cases {
            let encrypted = AuthUtils::encrypt(plaintext).unwrap();
            let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
            
            assert_eq!(plaintext, decrypted, "Failed for: {}", plaintext);
        }
    }

    #[test]
    fn test_encrypt_produces_different_outputs() {
        let plaintext = "Same input text";
        
        let encrypted1 = AuthUtils::encrypt(plaintext).unwrap();
        let encrypted2 = AuthUtils::encrypt(plaintext).unwrap();
        let encrypted3 = AuthUtils::encrypt(plaintext).unwrap();
        
        assert_ne!(encrypted1, encrypted2);
        assert_ne!(encrypted1, encrypted3);
        assert_ne!(encrypted2, encrypted3);
        
        assert_eq!(AuthUtils::decrypt(&encrypted1).unwrap(), plaintext);
        assert_eq!(AuthUtils::decrypt(&encrypted2).unwrap(), plaintext);
        assert_eq!(AuthUtils::decrypt(&encrypted3).unwrap(), plaintext);
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let result = AuthUtils::decrypt("not-valid-base64!!!");
        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_too_short_data() {
        let short_data = base64::engine::general_purpose::STANDARD.encode(b"short");
        let result = AuthUtils::decrypt(&short_data);
        
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too short"));
    }

    #[test]
    fn test_encrypt_decrypt_binary_data() {
        let binary_data = vec![0u8, 1, 2, 3, 255, 254, 0, 128];
        let plaintext = String::from_utf8_lossy(&binary_data);
        
        let encrypted = AuthUtils::encrypt(&plaintext).unwrap();
        let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encryption_performance() {
        let plaintext = "Performance test message";
        
        let start = std::time::Instant::now();
        for _ in 0..100 {
            let encrypted = AuthUtils::encrypt(plaintext).unwrap();
            let _decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        }
        let duration = start.elapsed();
        
        assert!(duration.as_millis() < 1000, "Encryption/decryption should be efficient");
    }

    #[test]
    fn test_encrypt_max_length() {
        let plaintext = "A".repeat(10_000);
        
        let encrypted = AuthUtils::encrypt(&plaintext).unwrap();
        let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_encrypt_decrypt_json_data() {
        let json_data = r#"
        {
            "user": {
                "id": 12345,
                "email": "test@example.com",
                "preferences": {
                    "theme": "dark",
                    "notifications": true
                }
            },
            "timestamp": "2023-01-01T00:00:00Z"
        }
        "#;
        
        let encrypted = AuthUtils::encrypt(json_data).unwrap();
        let decrypted = AuthUtils::decrypt(&encrypted).unwrap();
        
        assert_eq!(json_data, decrypted);
    }

    #[test]
    fn test_derive_key_from_string() {
        let input = "test_key";
        let key1 = derive_key_from_string(input);
        let key2 = derive_key_from_string(input);
        
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
        
        let key3 = derive_key_from_string("different_key");
        assert_ne!(key1, key3);
    }
}