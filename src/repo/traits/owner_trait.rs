use async_trait::async_trait;
use crate::models::owner::{Owner, OwnerLogin};
use mongodb::bson::oid::ObjectId;
use crate::utils::errors::ApiError;

#[async_trait]
pub trait OwnerTrait {
    async fn create_owner(&self, owner: Owner) -> Result<(), ApiError>;
    async fn login_owner(&self, credentials: OwnerLogin) -> Result<Option<Owner>, ApiError>;
    async fn get_all_owners(&self) -> Result<Vec<Owner>, ApiError>;
    async fn get_owner_by_id(&self, id: ObjectId) -> Result<Option<Owner>, ApiError>;
    async fn get_owner_by_email(&self, email: String) -> Result<Option<Owner>, ApiError>;
    async fn update_owner(&self, owner: Owner) -> Result<(), ApiError>;
    async fn delete_owner(&self, email: String) -> Result<(), ApiError>;
    async fn reset_password(&self, email: String, code: String) -> Result<(), ApiError>;
    async fn send_password_reset_email(&self, email: String) -> Result<(), ApiError>;
}