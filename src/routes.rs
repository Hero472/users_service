use std::sync::Arc;

use actix_web::web;

use crate::utils::config::AppConfig;
use crate::utils::security::jwt::JwtMiddleware;
use crate::api::handlers::user_handlers::{ask_recovery_password, confirm_recovery_password, create_user, login_user, set_new_password, verify_email};

pub fn public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .service(
                web::resource("/register")
                    .route(web::post().to(create_user))
            )
            .service(
                web::resource("/login")
                    .route(web::post().to(login_user))
            )
            .service(
                web::resource("/verify-email")
                    .route(web::post().to(verify_email))
            )
            .service(
                web::resource("/password/reset/request")
                    .route(web::post().to(ask_recovery_password))
            )
            .service(
                web::resource("/password/reset/verify")
                    .route(web::post().to(confirm_recovery_password))
            )
            .service(
                web::resource("/password/reset/confirm")
                    .route(web::post().to(set_new_password))
            )
    );
    
}
pub fn private_routes(cfg: &mut web::ServiceConfig) {

    let config = AppConfig::global();

    let jwt_middleware = JwtMiddleware {secret_key: Arc::new(config.secret_key.clone()) };

    cfg.service(
        web::resource("/private_endpoint")
            .wrap(jwt_middleware)
            .route(web::get().to(|| async { "This is a private endpoint" }))
    );
}

#[cfg(test)]
mod tests {
    use crate::{api::state::AppState, domain::email::{model::Email, service::EmailService}, infrastructure::{database::MongoContext, email_service::SmtpEmailService}, utils::ApiError};

    use super::*;
    use actix_web::{test, web, App, http::StatusCode};
    use serde_json::json;

    async fn create_test_app_state() -> AppState {
        let mongo_context = web::Data::new(MongoContext::init("uri", "test").await.unwrap());
        let smtp_service = web::Data::new(SmtpEmailService::new("localhost", "test@example.com", "a").unwrap());
        
        AppState {
            db: mongo_context,
            smtp: smtp_service,
        }
    }

    fn create_test_app_explicit() -> App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest, 
            Config = (), 
            Response = actix_web::dev::ServiceResponse, 
            Error = actix_web::Error,
            InitError = ()
        >
    > {
        App::new()
            .app_data(web::Data::new(create_test_app_state()))
            .configure(public_routes)
            .configure(private_routes)
    }

    // #[tokio::test]
    // async fn test_register_route() {
    //     let app = test::init_service(create_test_app_explicit()).await;
        
    //     let register_data = json!({
    //         "email": "test@example.com",
    //         "password": "password123",
    //         "name": "Test User",
    //         "last_name": "Last Name",
    //         "phone_number" : "123456"
    //     });

    //     let req = test::TestRequest::post()
    //         .uri("/auth/register")
    //         .set_json(&register_data)
    //         .to_request();
        
    //     let resp = test::call_service(&app, req).await;

    //     println!("Status: {}", resp.status());
    //     println!("Response: {:?}", resp.response().body());
    //     let body = test::read_body(resp).await;
    //     let body_str = String::from_utf8_lossy(&body);
    //     println!("Response body: {}", body_str);
    //     println!("=== END DEBUG ===");
        
    //     //assert!(resp.status().is_client_error() || resp.status().is_success());
    // }

    // #[tokio::test]
    // async fn test_login_route() {
    //     let app = test::init_service(create_test_app_explicit()).await;
        
    //     let login_data = json!({
    //         "email": "test@example.com",
    //         "password": "password123"
    //     });

    //     let req = test::TestRequest::post()
    //         .uri("/auth/login")
    //         .set_json(&login_data)
    //         .to_request();
        
    //     let resp = test::call_service(&app, req).await;
    //     assert!(resp.status().is_client_error() || resp.status().is_success());
    // }

    // #[tokio::test]
    // async fn test_password_reset_request_route() {
    //     let app = test::init_service(create_test_app_explicit()).await;
        
    //     let reset_data = json!({
    //         "email": "test@example.com"
    //     });

    //     let req = test::TestRequest::post()
    //         .uri("/auth/password/reset/request")
    //         .set_json(&reset_data)
    //         .to_request();
        
    //     let resp = test::call_service(&app, req).await;
    //     assert!(resp.status().is_client_error() || resp.status().is_success());
    // }

    // #[tokio::test]
    // async fn test_invalid_route_returns_404() {
    //     let app = test::init_service(create_test_app_explicit()).await;
        
    //     let req = test::TestRequest::get()
    //         .uri("/auth/nonexistent")
    //         .to_request();
        
    //     let resp = test::call_service(&app, req).await;
    //     assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    // }
}