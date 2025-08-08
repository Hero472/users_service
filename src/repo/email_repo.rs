use crate::{models::email::Email, repo::{database::MongoRepository, traits::email_trait::EmailTrait}, utils::errors::ApiError};

impl EmailTrait for MongoRepository {

    async fn send_email(&self, email: Email) -> Result<(), ApiError> {
        // Implementation for sending an email
        Ok(())
    }

    async fn send_password_reset_email(&self, email: String, reset_link: String) -> Result<(), ApiError> {
        // Implementation for sending a password reset email
        Ok(())
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