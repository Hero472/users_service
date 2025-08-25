use pets::{api::state::AppState, infrastructure::{database::mongo_context::MongoContext, smtp::email_service::SmtpEmailService}, routes::{private_routes, public_routes}};
use actix_web::{get, web, App, HttpServer, Responder};
use std::env;

#[get("/")]
async fn entry_point() -> impl Responder {
    "This is the Pets API. Use the /register endpoint to create an owner."
}

// TODO: I need to make a revovery of the account sending an email with a link to reset the password

#[tokio::main]
async fn main() -> std::io::Result<()> {


    dotenv::dotenv().ok();

    // TODO: confirm create account to confirm the email exists

    let email_service = SmtpEmailService::new(
        &env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
        &env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
        &env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
    ).expect("Failed to create EmailService");

    let db_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let mongo_context = match MongoContext::init(&db_url, "pets_db").await {
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
        println!("Creating new app instance");

        App::new()
            .app_data(app_state.clone())
            .configure(public_routes)
            .configure(private_routes)
            .service(entry_point)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}