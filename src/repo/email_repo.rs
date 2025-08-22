use async_trait::async_trait;

use crate::{models::email::Email, repo::{traits::email_trait::EmailTrait}, services::email::EmailService, utils::errors::ApiError};

#[async_trait]
impl EmailTrait for EmailService {

    async fn send_email(&self, email: Email) -> Result<(), ApiError> {
        self.send_email(&email)
            .await
            .map_err(|e| ApiError::InternalServerError(e.to_string()))
    }

    async fn send_password_reset_email(&self, email: String) -> Result<String, ApiError> {
        self.send_password_recovery(&email)
            .await
            .map_err(|e| ApiError::InternalServerError(e.to_string()))
    }

    async fn verify_email(&self, email: String, verification_code: String) -> Result<(), ApiError> {
        // Implementation for verifying an email
        Ok(())
    }

    async fn send_verification_email(&self, email: String) -> Result<(), ApiError> {
        // Implementation for sending a verification email
        Ok(())
    }
}