use actix_web::{web, HttpResponse, Responder, ResponseError};
use crate::models::owner::{Owner, OwnerLogin, OwnerReceive};
use crate::repo::database_repository::MongoRepository;
use crate::repo::traits::owner_trait::OwnerTrait;

pub async fn create_owner(
    repo: web::Data<MongoRepository>,
    owner: web::Json<OwnerReceive>
) -> impl Responder {
    let owner = Owner::new(owner.into_inner());
    match repo.create_owner(owner).await {
        Ok(_) => HttpResponse::Created().finish(),
        Err(e) => e.error_response()
    }
}

pub async fn login_owner(
    repo: web::Data<MongoRepository>,
    credentials: web::Json<OwnerLogin>
) -> impl Responder {
    match repo.login_owner(credentials.into_inner()).await {
        Ok(owner) => {
            if let Some(owner) = owner {
                return HttpResponse::Ok().json(owner.to_send());
            } else {
                return HttpResponse::Unauthorized().finish();
            }
        },
        Err(e) => e.error_response()
    }
}

pub async fn get_all_owners(
    repo: web::Data<MongoRepository>
) -> impl Responder {
    match repo.get_all_owners().await {
        Ok(owners) => HttpResponse::Ok().json(owners),
        Err(e) => e.error_response()
    }
}