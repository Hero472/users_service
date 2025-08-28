use actix_web::{web, HttpResponse, Responder, ResponseError};
use chrono::{Duration, Utc};
use crate::{api::state::AppState, domain::{email::service::EmailService, user::{model::{User, UserLoginReceive, UserRegisterReceive, UserRole, UserSend, VerifyEmail}, repository::UserRepository}}, infrastructure::mongodb::user_repository::MongoUserRepository, utils::{auth::AuthUtils, errors::ApiError}};

pub async fn create_user(
    state: web::Data<AppState>,
    user: web::Json<UserRegisterReceive>
) -> impl Responder {

    let encrypted_email = match AuthUtils::encrypt(&user.email) {
        Ok(email) => email,
        Err(_) => return HttpResponse::InternalServerError().json("Email encryption failed")
    };
    
    let encrypted_phone = match AuthUtils::encrypt(&user.phone_number) {
        Ok(phone) => phone,
        Err(_) => return HttpResponse::InternalServerError().json("Phone encryption failed")
    };

    let user_repo = MongoUserRepository::new(&state.db);

    let email_send = state
        .smtp
        .send_verification_email(&user.email)
        .await;

    if email_send.is_err() {
        HttpResponse::InternalServerError().finish();
    }

    let user = User {
        id: None,
        name: user.name.clone(),
        email: encrypted_email,
        email_hash: AuthUtils::hash(&user.email),
        password: AuthUtils::hash(&user.password),
        phone_number: encrypted_phone,
        role: UserRole::User,
        access_token: None,
        refresh_token: None,
        email_verified: false,
        verification_code: Some(email_send.unwrap()),
        verification_code_expires: Some(Utc::now() + Duration::minutes(30)),
        password_reset_code: None,
        password_reset_expires: None,
    };

    match user_repo.create_user(user).await {
        Ok(_) => HttpResponse::Created().finish(),
        Err(e) => e.error_response()
    }

}

pub async fn login_user(
    state: web::Data<AppState>,
    credentials: web::Json<UserLoginReceive>
) -> impl Responder {

    let user_repo = MongoUserRepository::new(&state.db);

    match user_repo.login_user(credentials.into_inner()).await {
        Ok(user) => {
            if let Some(user) = user {

                let phone_number = match AuthUtils::decrypt(&user.phone_number) {
                    Ok(phone) => phone,
                    Err(e) => return ApiError::InternalServerError(e.to_string()).error_response(),
                };

                let user_send = UserSend {
                    id: user.id,
                    name: user.name,
                    phone_number: phone_number,
                    email: user.email,
                    role: user.role,
                    access_token: user.access_token,
                };

                return HttpResponse::Ok().json(user_send);
            } else {
                return HttpResponse::Unauthorized().finish();
            }
        },
        Err(e) => e.error_response()
    }
}

pub async fn verify_email(
    state: web::Data<AppState>,
    credentials: web::Json<VerifyEmail>
) -> impl Responder {
    let user_repo = MongoUserRepository::new(&state.db);

    let email = credentials.email.clone();
    let code = credentials.code.clone();

    match user_repo.verify_email(email, code).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(e) => e.error_response()
    }
}

pub async fn ask_recovery_password(
    state: web::Data<AppState>,
    email: String
) {

}

pub async fn confirm_recovery_password(
    state: web::Data<AppState>,
    code: String
) {

}

pub async fn set_new_password(
    state: web::Data<AppState>,
    new_password: String
){

}

pub async fn get_all_users(
    state: web::Data<AppState>
) -> impl Responder {

    let user_repo = MongoUserRepository::new(&state.db);

    match user_repo.get_all_users().await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => e.error_response()
    }
}