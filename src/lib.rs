//! # ml-dsa-bip39
//!
//! BIP39 mnemonic derivation for ML-DSA (FIPS 204) post-quantum digital signatures.
//!
//! This crate provides deterministic keypair derivation from 24-word BIP39 mnemonics,
//! enabling portable backup and recovery of ML-DSA keys across devices.
//!
//! ## Features
//!
//! - **Deterministic**: Same mnemonic + passphrase always produces same keys
//! - **Level-agnostic**: Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87
//! - **BIP44-style paths**: Familiar derivation path format
//! - **Domain separation**: Each security level uses unique derivation paths
//! - **Backend-agnostic**: Abstract API allows swapping crypto implementations
//!
//! ## Quick Start
//!
//! ```rust
//! use ml_dsa_bip39::{MlDsaLevel, derive_keypair, mnemonic_to_seed};
//!
//! // Generate seed from mnemonic
//! let mnemonic = "abandon abandon abandon abandon abandon abandon \
//!                 abandon abandon abandon abandon abandon about";
//! let seed = mnemonic_to_seed(mnemonic, "")?;
//!
//! // Derive ML-DSA-44 keypair (default level)
//! let keypair = derive_keypair(&seed, 0, 0, MlDsaLevel::default())?;
//!
//! // Sign and verify
//! let message = b"Hello, post-quantum world!";
//! let signature = keypair.sign(message)?;
//! assert!(keypair.verify(message, &signature)?);
//! # Ok::<(), ml_dsa_bip39::Error>(())
//! ```
//!
//! ## Security Levels
//!
//! | Level | NIST Category | Security | Public Key | Signature |
//! |-------|---------------|----------|------------|-----------|
//! | ML-DSA-44 | 2 | 128-bit | 1,312 B | 2,420 B |
//! | ML-DSA-65 | 3 | 192-bit | 1,952 B | 3,309 B |
//! | ML-DSA-87 | 5 | 256-bit | 2,592 B | 4,627 B |
//!
//! ## Derivation Paths
//!
//! Each security level uses a unique purpose field to prevent collisions:
//!
//! - ML-DSA-44: `m/8844'/coin'/account'/0/index`
//! - ML-DSA-65: `m/8865'/coin'/account'/0/index`
//! - ML-DSA-87: `m/8887'/coin'/account'/0/index`

#![deny(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms)]

mod derivation;
mod error;
mod level;
mod types;

#[cfg(feature = "rustcrypto")]
mod backend_rustcrypto;

pub use derivation::{derive_keypair, derive_keypair_with_coin, mnemonic_to_seed};
pub use error::Error;
pub use level::MlDsaLevel;
pub use types::{MlDsaKeyPair, MlDsaSignature};

/// Result type for ml-dsa-bip39 operations
pub type Result<T> = std::result::Result<T, Error>;

/// Default coin type for Silica network (can be overridden)
pub const SILICA_COIN_TYPE: u32 = 1337;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_derivation() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        
        let keypair = derive_keypair(&seed, 0, 0, MlDsaLevel::default()).unwrap();
        
        // Verify key sizes for ML-DSA-44
        assert_eq!(keypair.public_key().len(), 1312);
        assert_eq!(keypair.seed().len(), 32);
    }

    #[test]
    fn test_determinism() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        
        let kp1 = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa44).unwrap();
        let kp2 = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa44).unwrap();
        
        assert_eq!(kp1.public_key(), kp2.public_key());
        assert_eq!(kp1.seed(), kp2.seed());
    }

    #[test]
    fn test_different_indices_different_keys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        
        let kp1 = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa44).unwrap();
        let kp2 = derive_keypair(&seed, 0, 1, MlDsaLevel::Dsa44).unwrap();
        
        assert_ne!(kp1.public_key(), kp2.public_key());
    }

    #[test]
    fn test_different_levels_different_keys() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        
        let kp44 = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa44).unwrap();
        let kp65 = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa65).unwrap();
        
        // Different levels = different keys (by design)
        assert_ne!(kp44.seed(), kp65.seed());
    }

    #[test]
    fn test_sign_verify() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        let keypair = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa44).unwrap();
        
        let message = b"test message";
        let signature = keypair.sign(message).unwrap();
        
        assert!(keypair.verify(message, &signature).unwrap());
        assert!(!keypair.verify(b"wrong message", &signature).unwrap());
    }
}
