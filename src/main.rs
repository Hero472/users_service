use users_service::{api::state::AppState, infrastructure::{database::mongo_context::MongoContext, smtp::email_service::SmtpEmailService}, routes::{private_routes, public_routes}, utils::config::AppConfig};
use actix_web::{get, web, App, HttpServer, Responder};


#[get("/")]
async fn entry_point() -> impl Responder {
    "This is the Users API. Use the /register endpoint to create an user."
}

// TODO: I need to make a recovery of the account sending an email with a link to reset the password

#[tokio::main]
async fn main() -> std::io::Result<()> {

    let config = AppConfig::global();

    let email_service = SmtpEmailService::new(
        &config.smtp_server,
        &config.smtp_username,
        &config.smtp_password
    ).expect("Failed to create EmailService");

    let mongo_context = match MongoContext::init(&config.database_url, "users").await {
        Ok(repo) => {
            println!("Connected to MongoDB successfully.");
            repo
        },
        Err(e) => {
            log::error!("Failed to connect to MongoDB: {}", e);
            std::process::exit(1);
        }
    };

    println!("🚀 Server running at http://localhost:8080");

    let mongo_data= web::Data::new(mongo_context);
    let email_data = web::Data::new(email_service);

    let app_state = AppState {db: mongo_data, smtp: email_data };

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(app_state.clone()))
            .configure(public_routes)
            .configure(private_routes)
            .service(entry_point)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}