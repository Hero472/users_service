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

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use temp_env;

    // #[test]
    // fn test_global_config_initialization() {
    //     temp_env::with_vars(vec![
    //         ("DATABASE_URL", Some("test_db_url")),
    //         ("SMTP_SERVER", Some("test_smtp_server")),
    //         ("SMTP_USERNAME", Some("test_smtp_user")),
    //         ("SMTP_PASSWORD", Some("test_smtp_pass")),
    //         ("EMAIL_USER", Some("test_email_user")),
    //         ("EMAIL_PASSWORD", Some("test_email_pass")),
    //         ("EMAIL_HOST", Some("test_email_host")),
    //         ("EMAIL_PORT", Some("587")),
    //         ("SECRET_KEY", Some("test_secret_key")),
    //         ("ENCRYPTION_KEY", Some("test_encryption_key")),
    //     ], || {
    //         let config = AppConfig::global();
            
    //         assert_eq!(config.database_url, "test_db_url");
    //         assert_eq!(config.smtp_server, "test_smtp_server");
    //         assert_eq!(config.email_port, "587");
    //     });
    // }

    #[test]
    fn test_config_is_singleton() {
        temp_env::with_vars(vec![
            ("DATABASE_URL", Some("test_db_url")),
            ("SMTP_SERVER", Some("test_smtp_server")),
            ("SMTP_USERNAME", Some("test_smtp_user")),
            ("SMTP_PASSWORD", Some("test_smtp_pass")),
            ("EMAIL_USER", Some("test_email_user")),
            ("EMAIL_PASSWORD", Some("test_email_pass")),
            ("EMAIL_HOST", Some("test_email_host")),
            ("EMAIL_PORT", Some("587")),
            ("SECRET_KEY", Some("test_secret_key")),
            ("ENCRYPTION_KEY", Some("test_encryption_key")),
        ], || {
            let config1 = AppConfig::global();
            let config2 = AppConfig::global();
            
            assert!(std::ptr::eq(config1, config2));
        });
    }

    // #[test]
    // fn test_config_values_are_correctly_loaded() {
    //     temp_env::with_vars(vec![
    //         ("DATABASE_URL", Some("test_db_url")),
    //         ("SMTP_SERVER", Some("test_smtp_server")),
    //         ("SMTP_USERNAME", Some("test_smtp_user")),
    //         ("SMTP_PASSWORD", Some("test_smtp_pass")),
    //         ("EMAIL_USER", Some("test_email_user")),
    //         ("EMAIL_PASSWORD", Some("test_email_pass")),
    //         ("EMAIL_HOST", Some("test_email_host")),
    //         ("EMAIL_PORT", Some("587")),
    //         ("SECRET_KEY", Some("test_secret_key")),
    //         ("ENCRYPTION_KEY", Some("test_encryption_key")),
    //     ], || {
    //         let config = AppConfig::global();
            
    //         assert!(!config.database_url.is_empty());
    //         assert!(!config.secret_key.is_empty());
    //         assert!(!config.encryption_key.is_empty());
    //         assert_eq!(config.email_port, "587");
    //     });
    // }

}