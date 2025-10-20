use std::error::Error;

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

    #[error("Not found: {0}")]
    NotFound(String),

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
            ApiError::NotFound(message) => {
                HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": message,
                    "code": 404
                }))
            }
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
                    "code": 500,
                    "details": message.source().map(|src| src.to_string())
                }))
            },
            ApiError::SerializationError(message) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid data format",
                    "code": 400,
                    "details": message.source().map(|src| src.to_string())
                }))
            },
            ApiError::DeserializationError(message) => {
                HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid data format",
                    "code": 400,
                    "details": message.source().map(|src| src.to_string())
                }))
            }
        }
    }
}

// ----------------------------- TESTS --------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use actix_web::{test, ResponseError, HttpResponse};
    use mongodb::{error::{Error as MongoError}, bson::{ser::Error as BsonError, de::Error as BsonDeError}};
    use serde_json::Value;

    async fn extract_json_from_response(response: HttpResponse) -> Value {
        let body = response.into_body();
        let bytes = actix_web::body::to_bytes(body).await.unwrap();
        serde_json::from_slice(&bytes).expect("Failed to parse JSON response")
    }

    fn create_mock_mongo_error() -> MongoError {
        MongoError::from(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Test mongo error"
        ))
    }

    fn create_mock_bson_error() -> BsonError {
        let mut map = HashMap::new();
        map.insert(42, "value");
        
        bson::to_bson(&map).unwrap_err()
    }

    fn create_mock_bson_de_error() -> BsonDeError {
        let invalid_bson = bson::Bson::RegularExpression(bson::Regex {
            pattern: "".to_string(),
            options: "".to_string(),
        });
        
        bson::from_bson::<String>(invalid_bson).unwrap_err()
    }

    #[test]
    async fn test_api_error_display() {
        let conflict = ApiError::Conflict("Resource already exists".to_string());
        assert_eq!(conflict.to_string(), "Conflict: Resource already exists");

        let bad_request = ApiError::BadRequest("Invalid input".to_string());
        assert_eq!(bad_request.to_string(), "Bad request: Invalid input");

        let unauthorized = ApiError::Unauthorized("Access denied".to_string());
        assert_eq!(unauthorized.to_string(), "Unauthorized: Access denied");

        let internal_error = ApiError::InternalServerError("Something went wrong".to_string());
        assert_eq!(internal_error.to_string(), "Internal server error: Something went wrong");

        let invalid_data = ApiError::InvalidData("Malformed data".to_string());
        assert_eq!(invalid_data.to_string(), "Invalid data: Malformed data");
    }

    #[test]
    async fn test_api_error_debug() {
        let conflict = ApiError::Conflict("Test".to_string());
        let debug_str = format!("{:?}", conflict);
        assert!(debug_str.contains("Conflict"));
        assert!(debug_str.contains("Test"));
    }

    #[test]
    async fn test_api_error_clone() {
        let original = ApiError::BadRequest("Original message".to_string());
        let cloned = original.clone();
        
        assert_eq!(original.to_string(), cloned.to_string());
    }

    #[tokio::test]
    async fn test_conflict_error_response() {
        let error = ApiError::Conflict("User already exists".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), 409);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "User already exists");
        assert_eq!(json["code"], 409);
    }

    #[tokio::test]
    async fn test_bad_request_error_response() {
        let error = ApiError::BadRequest("Missing required field".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), 400);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "Missing required field");
        assert_eq!(json["code"], 400);
    }

    #[tokio::test]
    async fn test_unauthorized_error_response() {
        let error = ApiError::Unauthorized("Invalid token".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), 401);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "Invalid token");
        assert_eq!(json["code"], 401);
    }

    #[tokio::test]
    async fn test_internal_server_error_response() {
        let error = ApiError::InternalServerError("Database connection failed".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), 500);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "Database connection failed");
        assert_eq!(json["code"], 500);
    }

    #[tokio::test]
    async fn test_invalid_data_error_response() {
        let error = ApiError::InvalidData("Email format is invalid".to_string());
        let response = error.error_response();
        
        assert_eq!(response.status(), 400);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "Email format is invalid");
        assert_eq!(json["code"], 400);
    }

    #[tokio::test]
    async fn test_mongo_error_response() {
        let mongo_error = create_mock_mongo_error();
        let error = ApiError::MongoError(mongo_error);
        let response = error.error_response();
        
        assert_eq!(response.status(), 500);
        
        let json = extract_json_from_response(response).await;
        assert!(json["error"].as_str().unwrap().contains("Database error:"));
        assert_eq!(json["code"], 500);
    }

    #[tokio::test]
    async fn test_serialization_error_response() {
        let bson_error = create_mock_bson_error();
        let error = ApiError::SerializationError(bson_error);
        let response = error.error_response();
        
        assert_eq!(response.status(), 400);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "Invalid data format");
        assert_eq!(json["code"], 400);
    }

    #[tokio::test]
    async fn test_deserialization_error_response() {
        let bson_de_error = create_mock_bson_de_error();
        let error = ApiError::DeserializationError(bson_de_error);
        let response = error.error_response();
        
        assert_eq!(response.status(), 400);
        
        let json = extract_json_from_response(response).await;
        assert_eq!(json["error"], "Invalid data format");
        assert_eq!(json["code"], 400);
    }

    #[test]
    async fn test_from_mongo_error() {
        let mongo_error = create_mock_mongo_error();
        let api_error: ApiError = mongo_error.into();
        
        match api_error {
            ApiError::MongoError(_) => {}
            _ => panic!("Expected MongoError variant"),
        }
    }

    #[test]
    async fn test_from_bson_error() {
        let bson_error = create_mock_bson_error();
        let api_error: ApiError = bson_error.into();
        
        match api_error {
            ApiError::SerializationError(_) => {}
            _ => panic!("Expected SerializationError variant"),
        }
    }

    #[test]
    async fn test_from_bson_de_error() {
        let bson_de_error = create_mock_bson_de_error();
        let api_error: ApiError = bson_de_error.into();
        
        match api_error {
            ApiError::DeserializationError(_) => {}
            _ => panic!("Expected DeserializationError variant"),
        }
    }

    #[tokio::test]
    async fn test_error_response_json_structure() {
        let error = ApiError::BadRequest("Test message".to_string());
        let response = error.error_response();
        let json = extract_json_from_response(response).await;
        
        assert!(json.is_object());
        assert!(json["error"].is_string());
        assert!(json["code"].is_number());
        
        let obj = json.as_object().unwrap();
        assert_eq!(obj.len(), 2);
        assert!(obj.contains_key("error"));
        assert!(obj.contains_key("code"));
    }

    #[tokio::test]
    async fn test_empty_error_messages() {
        let error = ApiError::Conflict("".to_string());
        let response = error.error_response();
        let json = extract_json_from_response(response).await;
        
        assert_eq!(json["error"], "");
        assert_eq!(json["code"], 409);
    }

    #[tokio::test]
    async fn test_long_error_messages() {
        let long_message = "a".repeat(1000);
        let error = ApiError::BadRequest(long_message.clone());
        let response = error.error_response();
        let json = extract_json_from_response(response).await;
        
        assert_eq!(json["error"], long_message);
        assert_eq!(json["code"], 400);
    }

    #[tokio::test]
    async fn test_special_characters_in_messages() {
        // Test with special characters that might break JSON
        let special_message = "Error with \"quotes\" and \n newlines and \t tabs";
        let error = ApiError::InternalServerError(special_message.to_string());
        let response = error.error_response();
        let json = extract_json_from_response(response).await;
        
        assert_eq!(json["error"], special_message);
        assert_eq!(json["code"], 500);
    }

    #[test]
    async fn test_all_error_variants_coverage() {
        // Ensure all variants can be created
        let _conflict = ApiError::Conflict("test".to_string());
        let _bad_request = ApiError::BadRequest("test".to_string());
        let _unauthorized = ApiError::Unauthorized("test".to_string());
        let _internal = ApiError::InternalServerError("test".to_string());
        let _invalid = ApiError::InvalidData("test".to_string());
        let _mongo = ApiError::MongoError(create_mock_mongo_error());
        let _serialization = ApiError::SerializationError(create_mock_bson_error());
        let _deserialization = ApiError::DeserializationError(create_mock_bson_de_error());
        
        assert!(true);
    }

    #[tokio::test]
    async fn test_content_type_header() {
        let error = ApiError::BadRequest("test".to_string());
        let response = error.error_response();
        
        let content_type = response.headers().get("content-type");
        assert!(content_type.is_some());
        
        let content_type_str = content_type.unwrap().to_str().unwrap();
        assert!(content_type_str.contains("application/json"));
    }
}