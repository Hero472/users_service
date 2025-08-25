use async_trait::async_trait;
use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use std::error::Error;
use lettre::{AsyncSmtpTransport, Tokio1Executor, AsyncTransport};

use rand::Rng;

use crate::domain::email::model::Email;
use crate::domain::email::service::EmailService;
use crate::utils::errors::ApiError;

#[derive(Clone)]
pub struct SmtpEmailService {
    username: String,
    mailer:  AsyncSmtpTransport<Tokio1Executor>
}

impl SmtpEmailService {

    pub fn new(smtp_server: &str, username: &str, password: &str) -> Result<Self, Box<dyn Error>> {
        let credentials = Credentials::new(username.to_string(), password.to_string());
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_server)?
            .credentials(credentials)
            .build();
        Ok(SmtpEmailService {
            username: username.to_string(),
            mailer
        })
    }

    pub async fn send_email_internal(&self, email: &Email) -> Result<(), Box<dyn Error>> {
        let message = Message::builder()
            .from(format!("Pets App <{}>", self.username).parse::<Mailbox>()?)
            .to(format!("<{}>", email.to).parse::<Mailbox>()?)
            .subject(&email.subject)
            .multipart(
                lettre::message::MultiPart::alternative_plain_html(
                    email.text_body.clone(),
                    email.html_body.clone(),
                )
            )?;

        self.mailer.send(message).await?;
        Ok(())
    }

    // TODO: I need to implement a storing system for this recovery code
    pub async fn send_password_recovery(&self, to: &str) -> Result<String, Box<dyn Error>> {

        let recovery_code = rand::rng().random_range(100000..999999).to_string();

        let email = Email {
            to: to.to_string(),
            subject: "Pets App Password Recovery".to_string(),
            html_body: format!(
                "<p>Hello,</p><p>Your password recovery code is: <strong>{}</strong></p>\
                 <p>If you did not request this, please ignore.</p>",
                recovery_code
            ),
            text_body: format!(
                "Hello,\n\nYour password recovery code is:\n\n{}\n\n\
                Please enter this code in the app to reset your password.\n\
                If you did not request a password reset, please ignore this email.\n\n\
                Best regards,\nPets App Team",
                recovery_code
            ),
        };

        self.send_email_internal(&email).await?;

        Ok(recovery_code)
    }
}

#[async_trait]
impl EmailService for SmtpEmailService {

    async fn send_email(&self, email: &Email) -> Result<(), ApiError> {
        self.send_email_internal(&email)
            .await
            .map_err(|e| ApiError::InternalServerError(e.to_string()))
    }

    async fn send_password_reset_email(&self, to: &str) -> Result<String, ApiError> {

        let recovery_code = rand::rng().random_range(100000..999999).to_string();

        let email = Email {
            to: to.to_string(),
            subject: "Pets App Password Recovery".to_string(),
            html_body: format!(
                "<p>Hello,</p><p>Your password recovery code is: <strong>{}</strong></p>\
                 <p>If you did not request this, please ignore.</p>",
                recovery_code
            ),
            text_body: format!(
                "Hello,\n\nYour password recovery code is:\n\n{}\n\n\
                Please enter this code in the app to reset your password.\n\
                If you did not request a password reset, please ignore this email.\n\n\
                Best regards,\nPets App Team",
                recovery_code
            ),
        };

        let email_sent = self.send_email_internal(&email)
            .await
            .map_err(|e| ApiError::InternalServerError(e.to_string()));
        

        match email_sent {
            Ok(_) => Ok(recovery_code),
            Err(_) => Err(email_sent.unwrap_err())
        }
    }

    async fn verify_email(&self, _email: &str, _verification_code: &str) -> Result<(), ApiError> {
        Ok(())
    }

    async fn send_verification_email(&self, _email: &str) -> Result<(), ApiError> {
        Ok(())
    }
}