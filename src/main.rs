use pets::{repo::database::MongoRepository, routes::{private_routes, public_routes}};
use pets::services::email::EmailService;
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


    let email_service = EmailService::new(
        &env::var("SMTP_SERVER").expect("SMTP_SERVER must be set"),
        &env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set"),
        &env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set"),
    ).expect("Failed to create EmailService");

    email_service.send_email("herodr@outlook.cl", "Test Email", "This is a test email from rust app")
        .await
        .expect("Failed to send test email");

    let db_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    let mongo: MongoRepository= match MongoRepository::init(&db_url, "pets_db").await {
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

    let mongo_data= web::Data::new(mongo);
    let email_data = web::Data::new(email_service);

    HttpServer::new(move || {
        println!("Creating new app instance");

        App::new()
            .app_data(mongo_data.clone())
            .app_data(email_data.clone())
            .configure(public_routes)
            .configure(private_routes)
            .service(entry_point)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}