use actix_web::web;

use crate::utils::jwt::JwtMiddleware;
use crate::api::handlers::user_handlers::{create_user, login_user, get_all_users};

pub fn public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/register")
            .route(web::post().to(create_user))
    );
    
    cfg.service(
        web::resource("/users")
            .route(web::get().to(get_all_users))
    );

    cfg.service(
        web::resource("/login")
            .route(web::post().to(login_user))
    );

}

pub fn private_routes(cfg: &mut web::ServiceConfig) {

    cfg.service(
        web::resource("/private_endpoint")
            .wrap(JwtMiddleware)
            .route(web::get().to(|| async { "This is a private endpoint" }))
    );
}