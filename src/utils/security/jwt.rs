use actix_web::{dev::{ServiceRequest, ServiceResponse}, HttpMessage};
use serde_json::Value;
use std::{rc::Rc, sync::Arc, task::{Context, Poll}};
use actix_web::Error;
use actix_service::{Service, Transform};
use futures::{future::{ok, LocalBoxFuture, Ready}};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

use crate::domain::UserRole;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims<T> {
    pub sub: String,
    pub exp: u64,
    pub iat: u64,
    pub data: T
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessData {
    pub role: UserRole,
    pub email: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RefreshData {
    pub jti: String,
}

pub struct JwtMiddleware {
    pub secret_key: Arc<String>
}

impl<S, B> Transform<S, ServiceRequest> for JwtMiddleware
where
    S: Service<ServiceRequest, Response = actix_web::dev::ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = actix_web::dev::ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(JwtMiddlewareService {
            service: Rc::new(service),
            secret_key: Arc::clone(&self.secret_key)
        })
    }
}

pub struct JwtMiddlewareService<S> {
    service: Rc<S>,
    secret_key: Arc<String>
}

impl<S, B> Service<ServiceRequest> for JwtMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        
        let auth_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => {
                return Box::pin(async {
                    Err(actix_web::error::ErrorUnauthorized("Authorization header missing"))
                })
            }
        };

        let auth_str = match auth_header.to_str() {
            Ok(str) => str,
            Err(_) => {
                return Box::pin(async {
                    Err(actix_web::error::ErrorUnauthorized("Invalid Authorization header encoding"))
                })
            }
        };

        if !auth_str.starts_with("Bearer ") {
            return Box::pin(async {
                Err(actix_web::error::ErrorUnauthorized("Authorization header must start with 'Bearer '"))
            })
        }

        let token = &auth_str[7..];

        if token.is_empty() {
            return Box::pin(async {
                Err(actix_web::error::ErrorUnauthorized("Empty token"))
            });
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;

        let token_data = decode::<Claims<Value>>(
            token,
            &DecodingKey::from_secret(self.secret_key.as_bytes()),
            &validation
        );

        match token_data {
            Ok(data) => {
                req.extensions_mut().insert(data.claims);
                return Box::pin(service.call(req))
            },
            Err(err) => {
                let error_msg = match err.kind() {
                    jsonwebtoken::errors::ErrorKind::ExpiredSignature => "Token expired",
                    jsonwebtoken::errors::ErrorKind::InvalidToken => "Invalid token",
                    jsonwebtoken::errors::ErrorKind::InvalidSignature => "Invalid token signature",
                    jsonwebtoken::errors::ErrorKind::InvalidEcdsaKey => "Invalid key",
                    jsonwebtoken::errors::ErrorKind::InvalidAlgorithm => "Invalid algorithm",
                    jsonwebtoken::errors::ErrorKind::InvalidIssuer => "Invalid issuer",
                    jsonwebtoken::errors::ErrorKind::InvalidAudience => "Invalid audience",
                    jsonwebtoken::errors::ErrorKind::InvalidSubject => "Invalid subject",
                    jsonwebtoken::errors::ErrorKind::ImmatureSignature => "Token not yet valid",
                    _ => "Invalid token", // Handles malformed_jwt_structure and other cases
                };

                Box::pin(async move {
                    Err(actix_web::error::ErrorUnauthorized(error_msg))
                })
            }
        }
    }
}

// TESTING

#[cfg(test)]
mod tests {
    use crate::utils::AppConfig;

    use super::*;
    use actix_web::{
        http::StatusCode, middleware::DefaultHeaders, test, web, App, HttpRequest, HttpResponse, Result as ActixResult
    };
    use jsonwebtoken::{encode, EncodingKey, Header};
    use chrono::{Utc, Duration};
    use serde_json::json;

    // Test handler that returns a simple response
    async fn test_handler(_req: HttpRequest) -> ActixResult<HttpResponse> {
        Ok(HttpResponse::Ok().json("Protected endpoint accessed"))
    }

    fn create_valid_token(email: &str, minutes_valid: i64) -> String {
        let config = AppConfig::global();
        
        let now = Utc::now();
        let expiration = now
            .checked_add_signed(Duration::minutes(minutes_valid))
            .expect("valid timestamp")
            .timestamp();

        let claims = Claims {
            sub: email.to_owned(),
            exp: expiration as u64,
            iat: now.timestamp() as u64,
            data: json!({
                "email": email,
                "created_at": now.to_rfc3339(),
                "token_type": "access"
            }),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(config.secret_key.as_ref()),
        ).unwrap()
    }

    fn create_expired_token(email: &str) -> String {
        create_valid_token(email, -60)
    }

    fn create_token_wrong_secret(email: &str) -> String {
        let now = Utc::now();
        let expiration = Utc::now()
            .checked_add_signed(Duration::minutes(60))
            .expect("valid timestamp")
            .timestamp() as usize;

        let claims = Claims {
            sub: email.to_owned(),
            exp: expiration as u64,
            iat: now.timestamp() as u64,
            data: json!({
                "email": email,
                "created_at": now.to_rfc3339(),
                "token_type": "access"
            }),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(b"wrong_secret_key"),
        ).unwrap()
    }

    #[tokio::test]
    async fn test_middleware_with_valid_token() {
        let config = AppConfig::global();
        let token = create_valid_token("test@example.com", 60);
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new(config.secret_key.clone())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);

        let body: String = test::read_body_json(resp).await;
        assert_eq!(body, "Protected endpoint accessed");
    }

    #[tokio::test]
    async fn test_middleware_with_missing_auth_header() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_malformed_auth_header() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        // Test without "Bearer " prefix
        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "invalid_token_format"))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_empty_bearer_token() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Bearer "))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_invalid_token() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Bearer invalid.jwt.token"))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_expired_token() {
        let expired_token = create_expired_token("test@example.com");
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", expired_token)))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_wrong_secret() {
        let wrong_token = create_token_wrong_secret("test@example.com");
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", wrong_token)))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_case_sensitivity() {
        let token = create_valid_token("test@example.com", 60);
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        // Test with lowercase "bearer"
        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("bearer {}", token)))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_extra_spaces() {
        let token = create_valid_token("test@example.com", 60);
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        // Test with extra spaces
        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer  {}", token))) // Extra space
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_different_users() {
        let config = AppConfig::global();
        let token1 = create_valid_token("user1@example.com", 60);
        let token2 = create_valid_token("user2@example.com", 60);
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new(config.secret_key.clone())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        // Test with first user
        let req1 = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", token1)))
            .to_request();

        let resp1 = test::call_service(&app, req1).await;
        assert_eq!(resp1.status(), 200);

        // Test with second user
        let req2 = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", token2)))
            .to_request();

        let resp2 = test::call_service(&app, req2).await;
        assert_eq!(resp2.status(), 200);
    }

    #[tokio::test]
    async fn test_middleware_multiple_requests_same_token() {
        let config = AppConfig::global();

        let token = create_valid_token("test@example.com", 60);
        
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new(config.secret_key.clone())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        for _i in 0..3 {
            let req = test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Authorization", format!("Bearer {}", token)))
                .to_request();

            let resp = test::call_service(&app, req).await;
            assert_eq!(resp.status(), 200);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_malformed_jwt_structure() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let test_cases = vec![
            "Bearer header.only",           // Missing signature
            "Bearer header.payload.sig.extra", // Too many parts
            "Bearer header",                // Only header
            "Bearer .",                    // Empty parts
            "Bearer ...",                  // Empty parts with separators
        ];

        for invalid_token in test_cases {
            let req = test::TestRequest::get()
                .uri("/protected")
                .insert_header(("Authorization", invalid_token))
                .to_request();

            let resp = test::try_call_service(&app, req).await;

            assert!(resp.is_err());
        
            if let Err(error) = resp {
                let error_response = error.error_response();
                assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
            }
        }
    }

    #[tokio::test]
    async fn test_middleware_with_non_utf8_header() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", "Bearer \x3D\x2A")) // Invalid UTF-8
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_with_very_long_token() {
        let app = test::init_service(
            App::new()
                .wrap(JwtMiddleware {secret_key: Arc::new("a".to_string())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let very_long_token = "a".repeat(10000);
        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", very_long_token)))
            .to_request();

        let resp = test::try_call_service(&app, req).await;

        assert!(resp.is_err());
    
        if let Err(error) = resp {
            let error_response = error.error_response();
            assert_eq!(error_response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn test_middleware_transform_creation() {
        // Test that the transform can be created
        let middleware = JwtMiddleware {secret_key: Arc::new("a".to_string())};
        
        // Create a mock service
        let _service = test::init_service(
            App::new().route("/test", web::get().to(|| async { HttpResponse::Ok() }))
        ).await;

        // This tests the new_transform method indirectly
        let _app_with_middleware = test::init_service(
            App::new()
                .wrap(middleware)
                .route("/test", web::get().to(|| async { HttpResponse::Ok() }))
        ).await;
    }

    #[test]
    async fn test_claims_serialization() {
        let claims = Claims {
            sub: "test@example.com".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            data: serde_json::json!({
                "email": "test@example.com",
                "role": "user"
            }),
        };

        // Test serialization
        let serialized = serde_json::to_string(&claims).unwrap();
        assert!(serialized.contains("test@example.com"));
        assert!(serialized.contains("1234567890"));

        // Test deserialization
        let deserialized: Claims<Value> = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.sub, claims.sub);
        assert_eq!(deserialized.exp, claims.exp);
    }

    #[test]
    async fn test_claims_debug() {
        let claims = Claims {
            sub: "test@example.com".to_string(),
            exp: 1234567890,
            iat: 1234567800,
            data: serde_json::json!({
                "email": "test@example.com",
                "role": "user"
            }),
        };

        let debug_str = format!("{:?}", claims);
        assert!(debug_str.contains("test@example.com"));
        assert!(debug_str.contains("1234567890"));
    }

    // Integration test combining middleware with other middleware
    #[tokio::test]
    async fn test_middleware_with_other_middleware() {
        let config = AppConfig::global();
        let token = create_valid_token("test@example.com", 60);
        
        let app = test::init_service(
            App::new()
                .wrap(DefaultHeaders::new().add(("X-Test", "test")))
                .wrap(JwtMiddleware {secret_key: Arc::new(config.secret_key.clone())})
                .route("/protected", web::get().to(test_handler))
        ).await;

        let req = test::TestRequest::get()
            .uri("/protected")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), 200);
        
        // Check that other middleware also worked
        assert_eq!(resp.headers().get("X-Test").unwrap(), "test");
    }
}