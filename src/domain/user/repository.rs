use async_trait::async_trait;
use mongodb::bson::oid::ObjectId;
use crate::{domain::user::model::{User, UserLoginReceive}, utils::errors::ApiError};

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create_user(&self, user: User) -> Result<(), ApiError>;
    async fn login_user(&self, credentials: UserLoginReceive) -> Result<Option<User>, ApiError>;
    async fn get_all_users(&self) -> Result<Vec<User>, ApiError>;
    async fn get_user_by_id(&self, id: ObjectId) -> Result<Option<User>, ApiError>;
    async fn get_user_by_email(&self, email: String) -> Result<Option<User>, ApiError>;
    async fn update_user(&self, user: User) -> Result<(), ApiError>;
    async fn delete_user(&self, email: String) -> Result<(), ApiError>;
    async fn verify_email(&self, email: String, code: String) -> Result<(), ApiError>;
    async fn reset_password_code_save(&self, email: String, code: String) -> Result<(), ApiError>;
    async fn verify_password_code(&self, email: String, code: String) -> Result<bool, ApiError>;
    async fn change_password(&self, email: String, code: String, password: String, confirm_pass: String) -> Result<bool, ApiError>;
}