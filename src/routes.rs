use actix_web::web;

use crate::utils::jwt::JwtMiddleware;
use crate::api::handlers::user_handlers::{ask_recovery_password, confirm_recovery_password, create_user, get_all_users, login_user, set_new_password, verify_email};

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
    
    cfg.service(
        web::scope("/users")
            .service(
                web::resource("")
                    .route(web::get().to(get_all_users))
            )
    );
}
pub fn private_routes(cfg: &mut web::ServiceConfig) {

    cfg.service(
        web::resource("/private_endpoint")
            .wrap(JwtMiddleware)
            .route(web::get().to(|| async { "This is a private endpoint" }))
    );
}