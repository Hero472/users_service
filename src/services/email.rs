use lettre::message::{Mailbox, Message};
use lettre::transport::smtp::authentication::Credentials;
use std::error::Error;
use lettre::{AsyncSmtpTransport, Tokio1Executor, AsyncTransport};

use rand::Rng;

use crate::models::email::Email;

pub struct EmailService {
    username: String,
    mailer:  AsyncSmtpTransport<Tokio1Executor>
}

impl EmailService {

    pub fn new(smtp_server: &str, username: &str, password: &str) -> Result<Self, Box<dyn Error>> {
        let credentials = Credentials::new(username.to_string(), password.to_string());
        let mailer = AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_server)?
            .credentials(credentials)
            .build();
        Ok(EmailService {
            username: username.to_string(),
            mailer
        })
    }

    pub async fn send_email(&self, email: &Email) -> Result<(), Box<dyn Error>> {
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

        self.send_email(&email).await?;

        Ok(recovery_code)
    }
}