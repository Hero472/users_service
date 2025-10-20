use async_trait::async_trait;

use crate::{domain::user::model::{CodeRequest, EmailRequest, PasswordResetRequest, User, UserLoginReceive}, utils::errors::ApiError};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: User, password: &str) -> Result<(), ApiError>;
    async fn login_user(&self, credentials: UserLoginReceive) -> Result<Option<User>, ApiError>;
    async fn get_all_users(&self) -> Result<Vec<User>, ApiError>; // not used
    async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, ApiError>;
    async fn update_user(&self, user: User) -> Result<(), ApiError>;
    async fn delete_user(&self, email: String) -> Result<(), ApiError>; // not used
    async fn verify_email(&self, email: String, code: String) -> Result<(), ApiError>;
    async fn reset_password_code_save(&self, request: EmailRequest, code: String) -> Result<(), ApiError>;
    async fn verify_password_code(&self, request: CodeRequest) -> Result<(), ApiError>;
    async fn change_password(&self, request: PasswordResetRequest) -> Result<(), ApiError>;
    fn validate_password_strength(&self, password: &str) -> Result<(), ApiError>;
    fn validate_email(&self, email: &str) -> Result<(), ApiError>;
}