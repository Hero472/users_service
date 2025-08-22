#[derive(Debug)]
pub struct Email {
    pub to: String,
    pub subject: String,
    pub html_body: String,
    pub text_body: String,
}