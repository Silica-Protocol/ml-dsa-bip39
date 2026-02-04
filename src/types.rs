//! Abstract types for ML-DSA keypairs and signatures
//!
//! These types are backend-agnostic - they don't expose any
//! implementation-specific types from ml-dsa, pqcrypto, etc.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, MlDsaLevel, Result};

#[cfg(feature = "rustcrypto")]
use crate::backend_rustcrypto;

/// ML-DSA keypair with backend-agnostic interface
///
/// Stores the 32-byte seed (not the expanded secret key) for compactness.
/// The signing key is regenerated from the seed when needed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MlDsaKeyPair {
    /// Security level (determines algorithm variant)
    #[zeroize(skip)]
    level: MlDsaLevel,
    /// 32-byte seed for key regeneration
    seed: [u8; 32],
    /// Public key (1312, 1952, or 2592 bytes depending on level)
    #[zeroize(skip)]
    public_key: Vec<u8>,
}

impl MlDsaKeyPair {
    /// Create a new keypair from seed and public key
    ///
    /// This is typically called by the backend implementation.
    pub(crate) fn new(level: MlDsaLevel, seed: [u8; 32], public_key: Vec<u8>) -> Self {
        Self {
            level,
            seed,
            public_key,
        }
    }

    /// Get the security level
    pub fn level(&self) -> MlDsaLevel {
        self.level
    }

    /// Get the 32-byte seed
    ///
    /// This can be used to recreate the signing key on any implementation.
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Sign a message
    ///
    /// Regenerates the signing key from the seed and signs the message.
    #[cfg(feature = "rustcrypto")]
    pub fn sign(&self, message: &[u8]) -> Result<MlDsaSignature> {
        backend_rustcrypto::sign(self, message)
    }

    /// Verify a signature
    #[cfg(feature = "rustcrypto")]
    pub fn verify(&self, message: &[u8], signature: &MlDsaSignature) -> Result<bool> {
        backend_rustcrypto::verify(&self.public_key, self.level, message, signature)
    }

    /// Get the derivation path used to create this keypair
    ///
    /// Format: `m/{purpose}'/{coin}'/{account}'/0/{index}`
    pub fn derivation_path(&self, coin: u32, account: u32, index: u32) -> String {
        format!(
            "m/{}'/{}'/{}'/0/{}",
            self.level.purpose(),
            coin,
            account,
            index
        )
    }
}

impl std::fmt::Debug for MlDsaKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlDsaKeyPair")
            .field("level", &self.level)
            .field("public_key_len", &self.public_key.len())
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

/// ML-DSA signature with level information
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlDsaSignature {
    /// Security level (determines expected signature size)
    level: MlDsaLevel,
    /// Raw signature bytes
    bytes: Vec<u8>,
}

impl MlDsaSignature {
    /// Create a new signature from bytes
    pub(crate) fn new(level: MlDsaLevel, bytes: Vec<u8>) -> Self {
        Self { level, bytes }
    }

    /// Parse signature from bytes with level hint
    pub fn from_bytes(level: MlDsaLevel, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != level.signature_size() {
            return Err(Error::InvalidSignature(format!(
                "expected {} bytes for {}, got {}",
                level.signature_size(),
                level,
                bytes.len()
            )));
        }
        Ok(Self {
            level,
            bytes: bytes.to_vec(),
        })
    }

    /// Get the signature bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the security level
    pub fn level(&self) -> MlDsaLevel {
        self.level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_debug_redacts_seed() {
        let keypair = MlDsaKeyPair::new(
            MlDsaLevel::Dsa44,
            [42u8; 32],
            vec![0u8; 1312],
        );
        
        let debug_output = format!("{:?}", keypair);
        assert!(debug_output.contains("[REDACTED]"));
        assert!(!debug_output.contains("42"));
    }

    #[test]
    fn test_signature_from_bytes_validates_size() {
        let result = MlDsaSignature::from_bytes(MlDsaLevel::Dsa44, &[0u8; 100]);
        assert!(result.is_err());
        
        let result = MlDsaSignature::from_bytes(MlDsaLevel::Dsa44, &[0u8; 2420]);
        assert!(result.is_ok());
    }
}
