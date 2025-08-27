use dotenv::dotenv;
use std::env;
use std::sync::OnceLock;

static CONFIG: OnceLock<AppConfig> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub database_url: String,
    pub smtp_server: String,
    pub smtp_username: String,
    pub smtp_password: String,
    pub email_user: String,
    pub email_password: String,
    pub email_host: String,
    pub email_port: String,
    pub secret_key: String,
    pub encryption_key: String,
}

impl AppConfig {

    pub fn global() -> &'static AppConfig {
        CONFIG.get_or_init(|| {
            dotenv().ok();

            AppConfig { 
                database_url: env::var("DATABASE_URL")
                    .expect("DATABASE_URL environment variable must be set"),
                smtp_server: env::var("SMTP_SERVER")
                    .expect("SMTP_SERVER environment variable must be set"),
                smtp_username: env::var("SMTP_USERNAME")
                    .expect("SMTP_USERNAME environment variable must be set"),
                smtp_password: env::var("SMTP_PASSWORD")
                    .expect("SMTP_PASSWORD environment variable must be set"),
                email_user: env::var("EMAIL_USER")
                    .expect("EMAIL_USER environment variable must be set"),
                email_password: env::var("EMAIL_PASSWORD")
                    .expect("EMAIL_PASSWORD environment variable must be set"),
                email_host: env::var("EMAIL_HOST")
                    .expect("EMAIL_HOST environment variable must be set"),
                email_port: env::var("EMAIL_PORT")
                    .expect("EMAIL_PORT environment variable must be set"),
                secret_key: env::var("SECRET_KEY")
                    .expect("SECRET_KEY environment variable must be set"),
                encryption_key: env::var("ENCRYPTION_KEY")
                    .expect("ENCRYPTION_KEY environment variable must be set"),
            }
        })
    }
}