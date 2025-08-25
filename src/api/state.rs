use actix_web::web::Data;

use crate::infrastructure::{database::mongo_context::MongoContext, smtp::email_service::SmtpEmailService};

#[derive(Clone)]
pub struct AppState {
    pub db: Data<MongoContext>,
    pub smtp: Data<SmtpEmailService>
}