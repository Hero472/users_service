use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use mongodb::bson::{self, doc};

use crate::infrastructure::database::mongo_context::MongoContext;
use crate::domain::user::repository::UserRepository;
use crate::domain::user::model::{CodeRequest, EmailRequest, PasswordResetRequest, User, UserLoginReceive};
use crate::utils::auth::AuthUtils;
use crate::utils::errors::ApiError;

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

        self.validate_email(&user.email)?;

        let email= AuthUtils::decrypt(&user.email)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        if let Some(_) = self.get_user_by_email(email).await? {
            return Err(ApiError::InvalidData("user with this email already exists".to_string()));
        }
        self.users.insert_one(&user).await?;
        Ok(())
    }

    async fn login_user(&self, credentials: UserLoginReceive) -> Result<Option<User>, ApiError> {
        let user = self.get_user_by_email(credentials.email).await?;

        if let Some(mut user) = user {
            // all credentials must be okay and also account must be active

            let pass = AuthUtils::verify_hash(&credentials.password, &user.password)
                .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

            if pass && user.email_verified {
                // Generate access token and refresh token
                let email= AuthUtils::decrypt(&user.email)
                    .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

                user.access_token = Some(AuthUtils::generate_token(&email, 30));
                user.refresh_token = Some(AuthUtils::generate_token(&email, 60*24*30));
                self.update_user(user.clone()).await?;
                return Ok(Some(user));
            } else {
                return Ok(None); // Password mismatch
            }
        }
        Ok(None) // Owner not found
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
 
    async fn get_user_by_email(&self, email: String) -> Result<Option<User>, ApiError> {

        let email_hash = AuthUtils::hash(&email)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        match self.users.find_one(doc! { "email_hash": email_hash }).await {
            Ok(user) => Ok(user),
            Err(e) => Err(ApiError::MongoError(e))
        }
    }

    async fn update_user(&self, user: User) -> Result<(), ApiError> {
        
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
        let user = self.get_user_by_email(email).await?;

        let mut user = user.ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        if user.email_verified {
            return Err(ApiError::Conflict("Email already verified".to_string()));
        }

        let verification_code = user.verification_code.as_ref()
            .ok_or_else(|| ApiError::BadRequest("No verification code found".to_string()))?;

        let verification_expiry = user.verification_code_expires
            .ok_or_else(|| ApiError::BadRequest("No verification expiry found".to_string()))?;

        // Verify code and expiry
        let code = AuthUtils::hash(&code)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        if verification_code != &code {
            return Err(ApiError::Unauthorized("Invalid verification code".to_string()));
        }

        if verification_expiry < Utc::now() {
            return Err(ApiError::Unauthorized("Verification code expired".to_string()));
        }

        user.email_verified = true;
        
        self.update_user(user).await

    }

    async fn reset_password_code_save(&self, request: EmailRequest, code: String) -> Result<(), ApiError> {
        
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);

        let mut user = self
            .get_user_by_email(request.email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;


        if !user.email_verified {
            return Err(ApiError::Conflict("Email must be verified before password reset".to_string()));
        }

        let code = AuthUtils::hash(&code)
            .map_err(|e| ApiError::InternalServerError(e.to_string()))?;

        user.password_reset_code = Some(code);
        user.password_reset_expires = Some(expires_at);

        self.update_user(user).await
      
    }
    
    async fn verify_password_code(&self, request: CodeRequest) -> Result<(), ApiError> {
        let user = self
            .get_user_by_email(request.email)
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

        // Check password strength
        if request.new_password.len() < 8 {
            return Err(ApiError::BadRequest("Password must be at least 8 characters".to_string()));
        }

        let mut user = self
            .get_user_by_email(request.email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        let new_password = AuthUtils::hash(&request.new_password)
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

        // I have no idea if this actually works but well more security is better I guess
        let disposable_domains = [
            "tempmail.com", "guerrillamail.com", "mailinator.com", "10minutemail.com",
            "throwaway.com", "fakeinbox.com", "yopmail.com", "disposable.com",
            "temp-mail.org", "trashmail.com"
        ];

        if let Some(domain) = email.split('@').nth(1) {
            if disposable_domains.iter().any(|&d| domain.eq_ignore_ascii_case(d)) {
                return Err(ApiError::InvalidData("Disposable email addresses are not allowed".to_string()));
            }
        }

        Ok(())
    }

}