use actix_web::web;

use crate::{handlers::owner_handlers::{create_owner, get_all_owners, login_owner}, utils::jwt::JwtMiddleware};

pub fn public_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::resource("/register")
            .route(web::post().to(create_owner))
    );
    
    cfg.service(
        web::resource("/owners")
            .route(web::get().to(get_all_owners))
    );

    cfg.service(
        web::resource("/login")
            .route(web::post().to(login_owner))
    );

}

pub fn private_routes(cfg: &mut web::ServiceConfig) {

    cfg.service(
        web::resource("/private_endpoint")
            .wrap(JwtMiddleware)
            .route(web::get().to(|| async { "This is a private endpoint" }))
    );
}