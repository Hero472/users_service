use async_trait::async_trait;
use chrono::Utc;
use futures::StreamExt;
use lettre::transport::smtp::commands::Auth;
use mongodb::bson::{self, doc};
use mongodb::bson::oid::ObjectId;

use crate::infrastructure::database::mongo_context::MongoContext;
use crate::domain::user::repository::UserRepository;
use crate::domain::user::model::{User, UserLoginReceive};
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
    
    async fn create_user(&self, user: User) -> Result<(), ApiError> {
        if user.email.is_empty() {
            return Err(ApiError::InvalidData("Email cannot be empty".to_string()));
        }

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
            if AuthUtils::verify_hash(&credentials.password, &user.password) && user.email_verified {
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

    async fn get_user_by_id(&self, id: ObjectId) -> Result<Option<User>, ApiError> {

        match self.users.find_one(doc! { "_id": id }).await {
            Ok(user) => Ok(user),
            Err(e) => Err(ApiError::MongoError(e))
        }
    }
 
    async fn get_user_by_email(&self, email: String) -> Result<Option<User>, ApiError> {

        match self.users.find_one(doc! { "email_hash": &AuthUtils::hash(&email) }).await {
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
        if verification_code != &code {
            return Err(ApiError::Unauthorized("Invalid verification code".to_string()));
        }

        if verification_expiry < Utc::now() {
            return Err(ApiError::Unauthorized("Verification code expired".to_string()));
        }

        user.email_verified = true;
        
        self.update_user(user).await

    }

    async fn reset_password_code_save(&self, email: String, code: String) -> Result<(), ApiError> {
        
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(15);

        let mut user = self
            .get_user_by_email(email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;


        if !user.email_verified {
            return Err(ApiError::Conflict("Email is not verified".to_string()));
        }

        user.password_reset_code = Some(code);
        user.password_reset_expires = Some(expires_at);

        self.update_user(user).await
      
    }
    
    async fn verify_password_code(&self, email: String, code: String) -> Result<bool, ApiError> {
        let user = self
            .get_user_by_email(email)
            .await?
            .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        if user.password_reset_code == Some(code) && user.password_reset_expires > Some(Utc::now()) {
            return Ok(true)
        } else {
            Ok(false)
        }

    }

    async fn change_password(&self, email: String, code: String, password: String, confirm_pass: String) -> Result<bool, ApiError> {

        let mut user = self
                    .get_user_by_email(email)
                    .await?
                    .ok_or_else(|| ApiError::NotFound("User not found".to_string()))?;

        if password == confirm_pass && user.password_reset_code == Some(code) {
            user.password = AuthUtils::hash(&password);
            let _ = self.update_user(user).await;
            Ok(true)
        } else {
            Ok(false)
        }
    }
}