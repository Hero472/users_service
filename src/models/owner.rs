use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;
use crate::utils::auth::AuthUtils;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Owner {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub last_name: String,
    pub phone_number: String,
    pub email: String,
    pub password: Vec<u8>,
    pub owned_pets: Vec<String>,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct OwnerReceive {
    pub name: String,
    pub last_name: String,
    pub phone_number: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct OwnerLogin {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct OwnerSend {
    pub id: Option<ObjectId>,
    pub name: String,
    pub last_name: String,
    pub phone_number: String,
    pub owned_pets: Vec<String>,
    pub access_token: Option<String>
}

impl Owner {
    pub fn new(
        owner_receive: OwnerReceive
    ) -> Self {
        Owner {
            id: None,
            name: owner_receive.name,
            last_name: owner_receive.last_name,
            phone_number: owner_receive.phone_number,
            email: AuthUtils::base64_encode(&owner_receive.email),
            password: AuthUtils::hash(&owner_receive.password),
            owned_pets: Vec::new(),
            access_token: None,
            refresh_token: None,
        }
    }

    pub fn to_send(&self) -> OwnerSend {
        OwnerSend {
            id: self.id,
            name: self.name.clone(),
            last_name: self.last_name.clone(),
            phone_number: self.phone_number.clone(),
            owned_pets: self.owned_pets.clone(),
            access_token: self.access_token.clone()
        }
    }

}