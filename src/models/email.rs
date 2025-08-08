use serde::Deserialize;

#[derive(Clone, Deserialize)]
pub struct SmtpConfig {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from_address: String,
    pub from_name: String,
}

#[derive(Debug)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}