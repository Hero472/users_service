use actix_web::{web, HttpResponse, Responder, ResponseError};
use crate::{api::state::AppState, domain::user::{model::{User, UserLoginReceive, UserRegisterReceive, UserRole, UserSend}, repository::UserRepository}, infrastructure::mongodb::user_repository::MongoUserRepository, utils::{auth::AuthUtils, errors::ApiError}};

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

    let user = User {
        id: None,
        name: user.name.clone(),
        email: encrypted_email,
        password: AuthUtils::hash(&user.password),
        phone_number: encrypted_phone,
        role: UserRole::User,
        owned_pets: vec![],
        access_token: None,
        refresh_token: None,
        active: false,
    };

    let user_repo = MongoUserRepository::new(&state.db);

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

pub async fn get_all_users(
    state: web::Data<AppState>
) -> impl Responder {

    let user_repo = MongoUserRepository::new(&state.db);

    match user_repo.get_all_users().await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => e.error_response()
    }
}