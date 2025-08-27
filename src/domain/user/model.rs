use serde::{Serialize, Deserialize};
use mongodb::bson::oid::ObjectId;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum UserRole {
    Admin,
    User
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub email: String,
    pub password: Vec<u8>,
    pub phone_number: String,
    pub role: UserRole,
    pub owned_pets: Vec<String>, // for now just String
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    pub active: bool
}

#[derive(Serialize, Deserialize)]
pub struct UserRegisterReceive {
    pub name: String,
    pub last_name: String,
    pub phone_number: String,
    pub email: String,
    pub password: String,
    pub role: UserRole, // The frontend tells us what role to create
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UserLoginReceive {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct UserSend {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub name: String,
    pub phone_number: String,
    pub email: String,
    pub role: UserRole,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}