# Authentication System

A secure user authentication system built with Rust, featuring user registration, login, email verification, and password recovery capabilities.

## Features

- **User Registration**: Create new user accounts with encrypted personal data
- **User Authentication**: Secure login with hashed passwords
- **Email Verification**: Email-based account verification system
- **Password Recovery**: Complete password reset workflow via email
- **Data Encryption**: Sensitive data (email, phone) is encrypted at rest
- **Role-based Access**: Support for Admin and User roles
- **MongoDB Integration**: Persistent data storage with MongoDB

## API Endpoints

### User Registration
POST /register

Creates a new user account and sends a verification email.

Request Body:
{
  "name": "John",
  "last_name": "Doe",
  "phone_number": "+1234567890",
  "email": "john.doe@example.com",
  "password": "Secur3_password"
}

Response:
- 201 Created: User successfully created
- 500 Internal Server Error: Registration failed

### User Login
POST /login

Authenticates a user and returns user information with access token.

Request Body:
{
  "email": "john.doe@example.com",
  "password": "Secur3_password"
}

Response:
{
  "id": "ObjectId",
  "name": "John",
  "phone_number": "+1234567890",
  "email": "john.doe@example.com",
  "role": "User",
  "access_token": "jwt_token_here"
}

### Email Verification
POST /verify-email

Verifies user email with the code sent during registration.

Request Body:
{
  "email": "john.doe@example.com",
  "code": "verification_code"
}

### Password Recovery - Request Reset
POST /forgot-password

Initiates password recovery by sending a reset code via email.

Request Body:
{
  "email": "john.doe@example.com"
}

### Password Recovery - Verify Code
POST /verify-reset-code

Verifies the password reset code sent via email.

Request Body:
{
  "email": "john.doe@example.com",
  "code": "reset_code"
}

### Password Recovery - Set New Password
POST /reset-password

Sets a new password after code verification.

Request Body:
{
  "email": "john.doe@example.com",
  "code": "reset_code",
  "new_password": "new_secure_password",
  "confirm_pass": "new_secure_password"
}

## Data Models

### User
The main user model stored in the database:
- id: MongoDB ObjectId (optional)
- name: User's name
- email: Encrypted email address
- email_hash: Hashed email for lookups
- password: Hashed password
- phone_number: Encrypted phone number
- role: User role (Admin/User)
- access_token: JWT access token (optional)
- refresh_token: JWT refresh token (optional)
- email_verified: Email verification status
- verification_code: Email verification code
- verification_code_expires: Verification code expiration
- password_reset_code: Password reset code
- password_reset_expires: Reset code expiration

### UserRole
pub enum UserRole {
    Admin,
    User
}

## Security Features

### Data Encryption
- Email addresses and phone numbers are encrypted before storage
- Uses AuthUtils::encrypt() and AuthUtils::decrypt() methods

### Password Security
- Passwords are hashed using secure hashing algorithms
- Uses AuthUtils::hash() for password hashing

### Email Verification
- 30-minute expiration for verification codes
- Prevents unauthorized account access

### Password Reset Security
- Time-limited reset codes
- Multi-step verification process

## Dependencies

Based on the code structure, this system likely uses:
- actix-web: Web framework for HTTP handling
- MongoDB: Database for user data persistence
- serde: Serialization/deserialization
- chrono: Date and time handling
- Custom AuthUtils: Encryption and hashing utilities
- SMTP client: For sending verification emails

## Setup Requirements

1. MongoDB Database: Configure connection to MongoDB instance
2. SMTP Server: Configure email service for verification and password reset
3. Environment Variables: Set up encryption keys and database credentials
4. Dependencies: Install required Rust crates

## Usage Example

use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/register", web::post().to(create_user))
            .route("/login", web::post().to(login_user))
            .route("/verify-email", web::post().to(verify_email))
            .route("/forgot-password", web::post().to(ask_recovery_password))
            .route("/verify-reset-code", web::post().to(confirm_recovery_password))
            .route("/reset-password", web::post().to(set_new_password))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

## Error Handling

The system uses custom error types and returns appropriate HTTP status codes:
- 201 Created: Successful user creation
- 200 OK: Successful operations
- 401 Unauthorized: Invalid credentials
- 500 Internal Server Error: Server-side errors

## Security Considerations

1. Encryption: Sensitive data is encrypted at rest
2. Hashing: Passwords are properly hashed
3. Time-limited Codes: Verification and reset codes expire
4. Input Validation: Validate all user inputs
5. HTTPS: Use HTTPS in production
6. Rate Limiting: Implement rate limiting for authentication endpoints

## Contributing

When contributing to this authentication system:
1. Ensure all sensitive data is properly encrypted
2. Follow secure coding practices
3. Add appropriate error handling
4. Update this README for any new features
5. Test all authentication flows thoroughly

## License

[Add your license information here]