use async_trait::async_trait;
use crate::{domain::email::model::Email, utils::errors::ApiError};

#[async_trait]
pub trait EmailService: Send + Sync {
    async fn send_email(&self, email: &Email) -> Result<(), ApiError>;
    async fn send_password_reset_email(&self, to: &str) -> Result<String, ApiError>;
    async fn send_verification_email(&self, email: &str) -> Result<(), ApiError>;
    async fn verify_email(&self, email: &str, verification_code: &str) -> Result<(), ApiError>;
}