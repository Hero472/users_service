use qrcode::{QrCode, EcLevel, Version};
use qrcode::render::unicode;
use std::time::SystemTime;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QRError {
    #[error("QR code generation failed: {0}")]
    GenerationError(String),

    #[error("Terminal display failed: {0}")]
    TerminalDisplayError(String),
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum QRErrorCorrection {
    Low,
    Medium,
    Quartile,
    High
}

impl From<QRErrorCorrection> for EcLevel {
    fn from(level: QRErrorCorrection) -> Self {
        match level {
            QRErrorCorrection::Low => EcLevel::L,
            QRErrorCorrection::Medium => EcLevel::M,
            QRErrorCorrection::Quartile => EcLevel::Q,
            QRErrorCorrection::High => EcLevel::H,
        }
    }
}

pub struct QR {
    pub data: String,
    pub is_activated: bool,
    pub created_at: SystemTime,
    pub address: String,
    pub charged: bool,
    pub charged_at: Option<SystemTime>,
    pub id: Vec<u8>,
    pub error_correction: QRErrorCorrection,
    pub version: Option<u8>,
}

impl QR {
    pub fn new(
        data: String,
        address: String,
        id: Vec<u8>,
    ) -> Self {
        QR {
            data,
            is_activated: false,
            created_at: SystemTime::now(),
            address,
            charged: false,
            charged_at: None,
            id,
            error_correction: QRErrorCorrection::High,
            version: Some(5)
        }
    }

    pub fn display_in_terminal(&self) -> Result<(), QRError> {
        let code = self.create_qr_code()?;
        let image = code.render::<unicode::Dense1x2>()
            .dark_color(unicode::Dense1x2::Dark)
            .light_color(unicode::Dense1x2::Light)
            .build();
        println!("{}", image);
        Ok(())
    }

    fn create_qr_code(&self) -> Result<QrCode, QRError> {
        match self.version {
            Some(ver) if (1..=40).contains(&ver) => {
                QrCode::with_version(
                    &self.data,
                    Version::Normal(ver.into()),
                    self.error_correction.into()
                ).map_err(|e| QRError::GenerationError(e.to_string()))
            }
            _ => QrCode::with_error_correction_level(
                &self.data,
                self.error_correction.into()
            ).map_err(|e| QRError::GenerationError(e.to_string()))
        }
    }
}