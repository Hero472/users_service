use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use mongodb::bson::{self, doc};

use crate::infrastructure::database::mongo_context::MongoContext;
use crate::domain::user::repository::UserRepository;
use crate::domain::user::model::{CodeRequest, EmailRequest, PasswordResetRequest, User, UserLoginReceive};
use crate::utils::security::auth::AuthUtils;
use crate::utils::errors::ApiError;

pub const DISPOSABLE_EMAIL_DOMAINS: [&str; 10] = [
    "tempmail.com",
    "guerrillamail.com", 
    "mailinator.com",
    "10minutemail.com",
    "throwaway.com",
    "fakeinbox.com",
    "yopmail.com",
    "disposable.com",
    "temp-mail.org",
    "trashmail.com",
];

pub struct MongoUserRepository {
    users: mongodb::Collection<User>
}

impl MongoUserRepository {
    pub fn new(context: &MongoContext) -> Self {
        Self {
            users: context.collection("users")
        }
    }
}

#[async_trait]
impl UserRepository for MongoUserRepository {
    
    async fn create_user(&self, user: User, password: &str) -> Result<(), ApiError> {
        self.validate_password_strength(&password)?;

        let email= AuthUtils::decrypt(&user.email)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        self.validate_email(&email)?;

        if let Some(existing_user) = self.get_user_by_email(&email).await? {
            if !existing_user.email_verified {
                return Err(ApiError::InvalidData(
                    "An account with this email already exists but is not verified. \
                    If you don't remember your password, please use the password recovery option.".to_string()
                ));
            } else {
                return Err(ApiError::InvalidData("User with this email already exists".to_string()));
            }
        }

        self.users.insert_one(&user).await?;
        Ok(())
    }

    async fn login_user(&self, credentials: UserLoginReceive) -> Result<Option<User>, ApiError> {
        let user = self.get_user_by_email(&credentials.email).await?;
        if let Some(mut user) = user {

            let pass = AuthUtils::verify_password(&credentials.password, &user.password)
                .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

            if pass && user.email_verified {
                let email= AuthUtils::decrypt(&user.email)
                    .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

                user.access_token = Some(AuthUtils::generate_access_token(&email, user.role.clone()));
                user.refresh_token = Some(AuthUtils::generate_refresh_token(&email));
                self.update_user(user.clone()).await?;
                return Ok(Some(user));
            } else {
                return Ok(None);
            }
        }
        Ok(None)
    }

    async fn get_all_users(&self) -> Result<Vec<User>, ApiError> {
        let mut cursor = self.users.find(doc! {}).await?;
        let mut users = Vec::new();

        while let Some(doc) = cursor.next().await {
            match doc {
                Ok(user) => {
                    users.push(user)
                },
                Err(e) => return Err(ApiError::MongoError(e)),
            }
        }
        Ok(users)
    }
 
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, ApiError> {

        let email_hash = AuthUtils::hash(email)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        match self.users.find_one(doc! { "email_hash": email_hash }).await { // it doesn't find because has is different
            Ok(user) => Ok(user),
            Err(e) => Err(ApiError::MongoError(e))
        }
    }

    async fn update_user(&self, mut user: User) -> Result<(), ApiError> {
        
        user.updated_at = Utc::now();

        let filter = doc! { "email_hash": user.email_hash.clone() };
        let update_doc = bson::to_bson(&user)?;

        if let bson::Bson::Document(document) = update_doc {
            let update = doc! {"$set": document };
            let result = self.users.update_one(filter, update).await?;

            if result.modified_count == 0 {
                return Err(ApiError::NotFound(format!(
                    "User with email_hash {} not found or no changes made", 
                    user.email_hash
                )));
            }
        } else {
            return Err(ApiError::InvalidData("Failed to convert user to BSON document".to_string()));
        }
        Ok(())
    }

    async fn delete_user(&self, email: String) -> Result<(), ApiError> {
        let filter = doc! { "email": &email };
        
        match self.users.delete_one(filter).await {
            Ok(_) => Ok(()),
            Err(e) => Err(ApiError::MongoError(e))
        }
    }

    async fn verify_email(&self, email: String, code: String) -> Result<(), ApiError> {
        let user = self.get_user_by_email(&email).await?;

        let mut user = user.ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        if user.email_verified {
            return Err(ApiError::Conflict("Email already verified".to_string()));
        }

        let verification_code = user.verification_code.as_ref()
            .ok_or_else(|| ApiError::BadRequest("No verification code found".to_string()))?;

        let verification_expiry = user.verification_code_expires
            .ok_or_else(|| ApiError::BadRequest("No verification expiry found".to_string()))?;

        let code = AuthUtils::hash(&code)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        if verification_code != &code {
            return Err(ApiError::Unauthorized("Invalid verification code".to_string()));
        }

        if verification_expiry < Utc::now() {
            return Err(ApiError::Unauthorized("Verification code expired".to_string()));
        }

        user.email_verified = true;
        user.verification_code = None;
        user.verification_code_expires = None;
        
        self.update_user(user).await

    }

    async fn reset_password_code_save(&self, request: EmailRequest, code: String) -> Result<(), ApiError> {
        
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);

        let mut user = self
            .get_user_by_email(&request.email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        let code = AuthUtils::hash(&code)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        user.password_reset_code = Some(code);
        user.password_reset_expires = Some(expires_at);

        self.update_user(user).await
      
    }
    
    async fn verify_password_code(&self, request: CodeRequest) -> Result<(), ApiError> {
        let user = self
            .get_user_by_email(&request.email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        let stored_code = user.password_reset_code
            .ok_or_else(|| ApiError::BadRequest("No reset code found".to_string()))?;
        
        let expiry = user.password_reset_expires
            .ok_or_else(|| ApiError::BadRequest("Reset code has no expiry".to_string()))?;
        
        if expiry < Utc::now() {
            return Err(ApiError::Unauthorized("Reset code has expired".to_string()));
        }

        let request_code = AuthUtils::hash(&request.code)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        if stored_code != request_code {
            return Err(ApiError::Unauthorized("Invalid reset code".to_string()));
        }

        Ok(())
    }

    async fn change_password(&self, request: PasswordResetRequest) -> Result<(), ApiError> {

        self.validate_password_strength(&request.new_password)?;

        self.verify_password_code(CodeRequest {
            email: request.email.clone(),
            code: request.code.clone(),
        }).await?;

        if request.new_password != request.confirm_pass {
            return Err(ApiError::BadRequest("Passwords do not match".to_string()));
        }

        if request.new_password.len() < 8 {
            return Err(ApiError::BadRequest("Password must be at least 8 characters".to_string()));
        }

        let mut user = self
            .get_user_by_email(&request.email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        let new_password = AuthUtils::hash_password(&request.new_password)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        user.password = new_password;
        user.password_reset_code = None;
        user.password_reset_expires = None;

        self.update_user(user).await?;
        
        Ok(())
    }

    fn validate_password_strength(&self, password: &str) -> Result<(), ApiError> {
        if password.len() < 8 {
            return Err(ApiError::InvalidData("Password must be at least 8 characters long".to_string()));
        }

        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_ascii_alphanumeric());

        let mut error_messages = Vec::new();

        if !has_uppercase {
            error_messages.push("at least one uppercase letter");
        }
        if !has_lowercase {
            error_messages.push("at least one lowercase letter");
        }
        if !has_digit {
            error_messages.push("at least one digit");
        }
        if !has_special {
            error_messages.push("at least one special character");
        }

        if !error_messages.is_empty() {
            let error_msg = format!("Password must contain: {}", error_messages.join(", "));
            return Err(ApiError::InvalidData(error_msg));
        }

        Ok(())
    }

    fn validate_email(&self, email: &str) -> Result<(), ApiError> {

        if email.is_empty() {
            return Err(ApiError::InvalidData("Email cannot be empty".to_string()));
        }

        if email.len() > 254 {
            return Err(ApiError::InvalidData("Email is too long".to_string()));
        }

        let email_regex = regex::Regex::new(
            r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        ).unwrap();

        if !email_regex.is_match(email) {
            return Err(ApiError::InvalidData("Invalid email format".to_string()));
        }

        if let Some(domain) = email.split('@').nth(1) {
            if DISPOSABLE_EMAIL_DOMAINS.iter().any(|&d| domain.eq_ignore_ascii_case(d)) {
                return Err(ApiError::InvalidData("Disposable email addresses are not allowed".to_string()));
            }
        }

        Ok(())
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use testcontainers::{runners::AsyncRunner, core::WaitFor};
    use testcontainers_modules::mongo::Mongo;

    fn create_test_user(email: &str) -> User {
        let email_hash = AuthUtils::hash(email).unwrap();
        let encrypted_email = AuthUtils::encrypt(email).unwrap();
        let password_hash = AuthUtils::hash_password("Test123!").unwrap();
        
        User {
            id: Some(bson::oid::ObjectId::new()),
            name: "Some_name".to_string(),
            email: encrypted_email,
            email_hash,
            phone_number: "123123".to_string(),
            password: password_hash,
            role: crate::domain::UserRole::User,
            email_verified: false,
            verification_code: Some(AuthUtils::hash("123456").unwrap()),
            verification_code_expires: Some(Utc::now() + chrono::Duration::hours(1)),
            password_reset_code: None,
            password_reset_expires: None,
            access_token: None,
            refresh_token: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }


    #[tokio::test]
    async fn test_create_user_success() {
    
        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let test_user = create_test_user("test@example.com");
    
        let result = repo.create_user(test_user, "ValidPass1!").await;

        assert!(result.is_ok(), "User creation should succeed: {:?}", result);
        
        let found_user = repo.get_user_by_email("test@example.com").await.unwrap();
        assert!(found_user.is_some(), "User should be found in database");

    }
    
    #[tokio::test]
    async fn test_create_user_duplicate_email() {

        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let test_user1 = create_test_user("duplicate@example.com");
        let test_user2 = create_test_user("duplicate@example.com");

        let result1 = repo.create_user(test_user1, "ValidPass1!").await;
        let _ = result1.clone().inspect_err(|e| println!("failed to read {}", e));
        assert!(result1.is_ok(), "First user creation should succeed");

        let result2 = repo.create_user(test_user2, "ValidPass1!").await;
        assert!(
            matches!(result2, Err(ApiError::InvalidData(_))),
            "Should fail with InvalidData for duplicate email: {:?}", result2
        );
    }

    #[tokio::test]
    async fn test_create_user_duplicate_unverified_email() {
        
        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let mut test_user1 = create_test_user("unverified@example.com");
        test_user1.email_verified = false;
        
        let test_user2 = create_test_user("unverified@example.com");

        let result1 = repo.create_user(test_user1, "ValidPass1!").await;
        assert!(result1.is_ok());

        let result2 = repo.create_user(test_user2, "ValidPass1!").await;
        
        match result2 {
            Err(ApiError::InvalidData(msg)) => {
                assert!(
                    msg.contains("not verified") || msg.contains("already exists"),
                    "Error message should mention unverified account: {}",
                    msg
                );
            }
            other => panic!("Expected InvalidData error, got: {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_create_user_weak_password() {
        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let test_user = create_test_user("weakpass@example.com");

        let weak_passwords = vec![
            "short",           // Too short
            "nouppercase1!",   // No uppercase
            "NOLOWERCASE1!",   // No lowercase  
            "NoDigits!",       // No digits
            "NoSpecial123",    // No special chars
        ];

        for password in weak_passwords {
            let result = repo.create_user(test_user.clone(), password).await;
            assert!(
                matches!(result, Err(ApiError::InvalidData(_))),
                "Weak password '{}' should be rejected: {:?}",
                password,
                result
            );
        }
    }

    #[tokio::test]
    async fn test_create_user_invalid_email() {
        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let invalid_emails = vec![
            "invalid-email",           // No @ symbol
            "user@mailinator.com",     // Disposable domain
            "",                        // Empty email
        ];

        for email in invalid_emails {
            let test_user = create_test_user(email);
            let result = repo.create_user(test_user, "ValidPass1!").await;
            
            assert!(
                matches!(result, Err(ApiError::InvalidData(_))),
                "Invalid email '{}' should be rejected: {:?}",
                email,
                result
            );
        }
    }

     #[tokio::test]
    async fn test_create_user_verification_code_preserved() {
        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let test_user = create_test_user("verification@example.com");

        let result = repo.create_user(test_user, "ValidPass1!").await;
        assert!(result.is_ok());

        let found_user = repo.get_user_by_email("verification@example.com").await.unwrap().unwrap();
        
        assert!(
            found_user.verification_code.is_some(),
            "Verification code should be preserved"
        );
        assert!(
            found_user.verification_code_expires.is_some(),
            "Verification expiry should be preserved"
        );
        assert!(
            !found_user.email_verified,
            "New user should not be email verified"
        );
    }

    #[tokio::test]
    async fn test_validate_email_too_long() {
        let container = Mongo::default().start().await.unwrap();
        let host = container.get_host().await.unwrap();
        let port = container.get_host_port_ipv4(27017).await.unwrap();
        let connection_string = format!("mongodb://{}:{}", host, port);
        let mongo_context = MongoContext::init(&connection_string, "test_db")
            .await
            .expect("Failed to connect to MongoDB");
        let repo = MongoUserRepository::new(&mongo_context);

        let long_email_255 = format!("{}@a.com", "a".repeat(249));
        let long_email_254 = format!("{}@a.com", "a".repeat(248));

        let test_cases = vec![
            ("short@example.com".to_string(), true, "normal email"),
            (long_email_255, false, "255 chars - too long"), 
            (long_email_254, true, "254 chars - at limit"),
            ("".to_string(), false, "empty email"),
        ];

        for (email, should_be_valid, description) in test_cases {
            let result = repo.validate_email(&email);
            assert_eq!(
                result.is_ok(), 
                should_be_valid,
                "Failed for case: {} - email: '{}', length is: {}",
                description, 
                if email.len() > 50 { format!("{}...", &email[..50]) } else { email.to_string() },
                email.len()
            );
        }
    }
}