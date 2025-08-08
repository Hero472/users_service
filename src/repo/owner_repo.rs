use async_trait::async_trait;
use futures::StreamExt;
use mongodb::bson::oid::ObjectId;
use crate::models::owner::{Owner, OwnerLogin};
use crate::repo::database::MongoRepository;
use crate::repo::traits::owner_trait::OwnerTrait;
use crate::utils::auth::AuthUtils;
use mongodb::bson::{doc, from_document, to_document, Document};
use crate::utils::errors::ApiError;

#[async_trait]
impl OwnerTrait for MongoRepository {

    async fn create_owner(&self, owner: Owner) -> Result<(), ApiError> {
        let collection = self.collection::<Document>("owners");
        if owner.email.is_empty() {
            return Err(ApiError::InvalidData("Email cannot be empty".to_string()));
        }
        if let Some(_) = self.get_owner_by_email(owner.email.clone()).await? {
            return Err(ApiError::InvalidData("Owner with this email already exists".to_string()));
        }
        let owner_doc = to_document(&owner)?;
        collection.insert_one(owner_doc).await?;
        Ok(())
    }
    
    async fn login_owner(&self, credentials: OwnerLogin) ->  Result<Option<Owner>, ApiError> {
        let owner = self.get_owner_by_email(credentials.email).await?;

        if let Some(mut owner) = owner {
            if AuthUtils::verify_hash(&credentials.password, &owner.password) {
                // Generate access token and refresh token
                owner.access_token = Some(AuthUtils::generate_token(owner.email.as_str(), 30));
                owner.refresh_token = Some(AuthUtils::generate_token(&owner.email.as_str(), 60*24*30));
                self.update_owner(owner.clone()).await?;
                return Ok(Some(owner));
            } else {
                return Ok(None); // Password mismatch
            }
        }
        Ok(None) // Owner not found
    }
    
    async fn get_all_owners(&self) -> Result<Vec<Owner>, ApiError> {
        let collection = self.collection::<Document>("owners");
        let mut cursor = collection.find(doc! {}).await?;
        let mut owners = Vec::new();
        
        while let Some(doc) = cursor.next().await {
            match doc {
                Ok(document) => {
                    if let Ok(owner) = from_document::<Owner>(document) {
                        owners.push(owner);
                    }
                },
                Err(e) => return Err(ApiError::MongoError(e)),
            }
        }
        
        Ok(owners)
    }

    async fn get_owner_by_id(&self, id: ObjectId) -> Result<Option<Owner>, ApiError> {
        let collection = self.collection::<Document>("owners");
        let owner = collection.find_one(doc! { "_id": id }).await?;

        if let Some(doc) = owner {
            let owner: Owner = from_document(doc)?;
            return Ok(Some(owner));
        } else {
            return Ok(None);
        }
    }
    
    async fn get_owner_by_email(&self, email: String) ->  Result<Option<Owner>, ApiError> {
        let collection = self.collection::<Document>("owners");
        let owner = collection.find_one(doc! { "email": &email }).await?;

        if let Some(doc) = owner {
            let owner: Owner = from_document(doc)?;
            return Ok(Some(owner));
        } else {
            return Ok(None);
        }
    }
    
    async fn update_owner(&self, owner: Owner) -> Result<(), ApiError> {
        let collection = self.collection::<Document>("owners");
        let filter = doc! { "email": &owner.email };
        let update_doc = to_document(&owner)?;
        collection.replace_one(filter, update_doc).await?;
        Ok(())
    }
    
    async fn delete_owner(&self, email: String) ->  Result<(), ApiError> {
        let collection = self.collection::<Document>("owners");
        let filter = doc! { "email": &email };
        collection.delete_one(filter).await?;
        Ok(())
    }

    async fn reset_password(&self, email: String, code: String) -> Result<(), ApiError> {
        // here the logic to reset the password will be implemented
        todo!();
    }

    async fn send_password_reset_email(&self, email: String) -> Result<(), ApiError> {
        // here the logic to send the password reset email with a code
        todo!();
    }
}