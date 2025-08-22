use actix_web::{web, HttpResponse, Responder, ResponseError};

use crate::{models::email::Email, repo::{database_repository::MongoRepository, traits::email_trait::EmailTrait}};

pub async fn send_email(
    repo: web::Data<MongoRepository>,
    email: web::Json<Email>
) -> impl Responder {
    match repo.get_email_service()
        .send_email(&email.into_inner())
        .await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => e.error_response()
    }
}

pub async fn send_password_reset_email(
    repo: web::Data<MongoRepository>,
    email: web::Json<String>
) -> impl Responder {
    match repo.get_email_service().send_password_reset_email(email).await {

    }

}