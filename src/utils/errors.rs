use actix_web::{HttpResponse, ResponseError};
use mongodb::{bson, error::Error as MongoError};
use thiserror::Error;
use bson::ser::Error as BsonError;
use bson::de::Error as BsonDeError;

#[derive(Debug, Error, Clone)]
pub enum ApiError {
    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Invalid data: {0}")]
    InvalidData(String),

    #[error(transparent)]
    MongoError(#[from] MongoError),

    #[error("Serialization error")]
    SerializationError(#[from] BsonError),

    #[error("Deserialization error")]
    DeserializationError(#[from] BsonDeError)
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        match self {
            ApiError::Conflict(message) => {
                HttpResponse::Conflict().json(serde_json::json!({
                    "error": message,
                    "code": 409
                }))
            },
            ApiError::BadRequest(message) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": message,
                    "code": 400
                }))
            },
            ApiError::Unauthorized(message) => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": message,
                    "code": 401
                }))
            },
            ApiError::InternalServerError(message) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": message,
                    "code": 500
                }))
            },
            ApiError::InvalidData(message) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": message,
                    "code": 400
                }))
            },
            ApiError::MongoError(message) => {
                HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": format!("Database error: {}", message),
                    "code": 500
                }))
            },
            ApiError::SerializationError(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid data format",
                    "code": 400
                }))
            },
            ApiError::DeserializationError(_) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid data format",
                    "code": 400
                }))
            }
        }
    }
}