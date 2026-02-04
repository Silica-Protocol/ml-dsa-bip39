//! ML-DSA security level definitions

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// ML-DSA security levels (FIPS 204)
///
/// Each level provides different security/performance tradeoffs:
///
/// | Level | NIST Category | Security | Public Key | Signature |
/// |-------|---------------|----------|------------|-----------|
/// | Dsa44 | 2 | 128-bit | 1,312 B | 2,420 B |
/// | Dsa65 | 3 | 192-bit | 1,952 B | 3,309 B |
/// | Dsa87 | 5 | 256-bit | 2,592 B | 4,627 B |
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MlDsaLevel {
    /// ML-DSA-44 (equivalent to Dilithium2)
    /// 128-bit security, smallest signatures
    /// **Default for most use cases**
    Dsa44,
    
    /// ML-DSA-65 (equivalent to Dilithium3)
    /// 192-bit security, medium signatures
    /// For high-value accounts (treasury, governance)
    Dsa65,
    
    /// ML-DSA-87 (equivalent to Dilithium5)
    /// 256-bit security, largest signatures
    /// Maximum security, reserved for critical infrastructure
    Dsa87,
}

impl Default for MlDsaLevel {
    fn default() -> Self {
        Self::Dsa44
    }
}

impl MlDsaLevel {
    /// Domain separator for key derivation (unique per level)
    ///
    /// This ensures that the same mnemonic produces different keys
    /// for different security levels.
    pub fn domain_separator(&self) -> &'static [u8] {
        match self {
            Self::Dsa44 => b"ML-DSA-BIP39:ML-DSA-44:V1",
            Self::Dsa65 => b"ML-DSA-BIP39:ML-DSA-65:V1",
            Self::Dsa87 => b"ML-DSA-BIP39:ML-DSA-87:V1",
        }
    }

    /// BIP44-style purpose field (unique per level)
    ///
    /// - ML-DSA-44: 8844
    /// - ML-DSA-65: 8865
    /// - ML-DSA-87: 8887
    pub fn purpose(&self) -> u32 {
        match self {
            Self::Dsa44 => 8844,
            Self::Dsa65 => 8865,
            Self::Dsa87 => 8887,
        }
    }

    /// Public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            Self::Dsa44 => 1312,
            Self::Dsa65 => 1952,
            Self::Dsa87 => 2592,
        }
    }

    /// Signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Dsa44 => 2420,
            Self::Dsa65 => 3309,
            Self::Dsa87 => 4627,
        }
    }

    /// ML-DSA seed size (always 32 bytes for all levels)
    pub fn seed_size(&self) -> usize {
        32
    }

    /// NIST security category
    pub fn nist_category(&self) -> u8 {
        match self {
            Self::Dsa44 => 2,
            Self::Dsa65 => 3,
            Self::Dsa87 => 5,
        }
    }

    /// Security level in bits
    pub fn security_bits(&self) -> u16 {
        match self {
            Self::Dsa44 => 128,
            Self::Dsa65 => 192,
            Self::Dsa87 => 256,
        }
    }

    /// Human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Dsa44 => "ML-DSA-44",
            Self::Dsa65 => "ML-DSA-65",
            Self::Dsa87 => "ML-DSA-87",
        }
    }
}

impl std::fmt::Display for MlDsaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_dsa44() {
        assert_eq!(MlDsaLevel::default(), MlDsaLevel::Dsa44);
    }

    #[test]
    fn test_unique_purposes() {
        let purposes: Vec<u32> = [MlDsaLevel::Dsa44, MlDsaLevel::Dsa65, MlDsaLevel::Dsa87]
            .iter()
            .map(|l| l.purpose())
            .collect();
        
        // All purposes must be unique
        let mut unique = purposes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(purposes.len(), unique.len());
    }

    #[test]
    fn test_unique_domain_separators() {
        let domains: Vec<&[u8]> = [MlDsaLevel::Dsa44, MlDsaLevel::Dsa65, MlDsaLevel::Dsa87]
            .iter()
            .map(|l| l.domain_separator())
            .collect();
        
        assert_ne!(domains[0], domains[1]);
        assert_ne!(domains[1], domains[2]);
        assert_ne!(domains[0], domains[2]);
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(MlDsaLevel::Dsa44.public_key_size(), 1312);
        assert_eq!(MlDsaLevel::Dsa65.public_key_size(), 1952);
        assert_eq!(MlDsaLevel::Dsa87.public_key_size(), 2592);
    }
}
