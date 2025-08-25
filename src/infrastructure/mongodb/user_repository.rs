use async_trait::async_trait;
use futures::StreamExt;
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
            if AuthUtils::verify_hash(&credentials.password, &user.password) {
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

        match self.users.find_one(doc! { "email": &email }).await {
            Ok(user) => Ok(user),
            Err(e) => Err(ApiError::MongoError(e))
        }
    }

    
    
    async fn update_user(&self, user: User) -> Result<(), ApiError> {

        // TODO: PUT THIS INTO FN
        let email= AuthUtils::decrypt(&user.email)
                    .map_err(|e| ApiError::InternalServerError(e.to_string()))?;
        
        let filter = doc! { "email": email };
        let update_doc = bson::to_bson(&user)?;

        if let bson::Bson::Document(document) = update_doc {
            let update = doc! {"$set": document };
            self.users.update_one(filter, update).await?;
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

    
    
    async fn reset_password(&self, _email: String, _code: String) -> Result<(), ApiError> {
        todo!()
    }

    
    async fn send_password_reset_email(&self, _email: String) -> Result<(), ApiError> {
        todo!()
    }
}