//! Error types for ml-dsa-bip39

use thiserror::Error;

/// Errors that can occur during ML-DSA derivation and operations
#[derive(Debug, Error)]
pub enum Error {
    /// Invalid mnemonic phrase
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    /// Invalid seed length
    #[error("Invalid seed length: expected 64 bytes, got {0}")]
    InvalidSeedLength(usize),

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Signing failed
    #[error("Signing failed: {0}")]
    SigningFailed(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Unsupported security level
    #[error("Unsupported ML-DSA level: {0}")]
    UnsupportedLevel(String),
}
