use async_trait::async_trait;
use crate::utils::errors::ApiError;

#[async_trait]
pub trait EmailTrait {
    async fn send_email(&self, to: String, subject: String, body: String) -> Result<(), ApiError>;
    async fn send_password_reset_email(&self, email: String, reset_link: String) -> Result<(), ApiError>;
    async fn verify_email(&self, email: String, verification_code: String) -> Result<(), ApiError>;
    async fn send_verification_email(&self, email: String) -> Result<(), ApiError>;
}