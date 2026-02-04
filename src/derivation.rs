//! Core derivation functions for BIP39 → ML-DSA
//!
//! Uses SHAKE256 to deterministically derive ML-DSA seeds from BIP39 seeds.

use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{Error, MlDsaKeyPair, MlDsaLevel, Result, SILICA_COIN_TYPE};

#[cfg(feature = "rustcrypto")]
use crate::backend_rustcrypto;

/// Convert a BIP39 mnemonic phrase to a 64-byte seed
///
/// # Arguments
/// * `mnemonic` - Space-separated BIP39 mnemonic words (12, 15, 18, 21, or 24 words)
/// * `passphrase` - Optional passphrase (empty string for none)
///
/// # Returns
/// 64-byte BIP39 seed
///
/// # Example
/// ```
/// use ml_dsa_bip39::mnemonic_to_seed;
///
/// let seed = mnemonic_to_seed(
///     "abandon abandon abandon abandon abandon abandon \
///      abandon abandon abandon abandon abandon about",
///     ""
/// )?;
/// assert_eq!(seed.len(), 64);
/// # Ok::<(), ml_dsa_bip39::Error>(())
/// ```
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 64]> {
    let mnemonic = bip39::Mnemonic::parse_normalized(mnemonic)
        .map_err(|e| Error::InvalidMnemonic(e.to_string()))?;
    
    let seed = mnemonic.to_seed(passphrase);
    
    Ok(seed)
}

/// Derive an ML-DSA keypair from a BIP39 seed
///
/// Uses the default Silica coin type (1337).
///
/// # Arguments
/// * `seed` - 64-byte BIP39 seed
/// * `account` - Account index (usually 0)
/// * `index` - Key index within the account
/// * `level` - ML-DSA security level
///
/// # Derivation Path
/// `m/{purpose}'/{coin}'/{account}'/0/{index}`
///
/// Where purpose is level-specific: 8844, 8865, or 8887
///
/// # Example
/// ```
/// use ml_dsa_bip39::{derive_keypair, mnemonic_to_seed, MlDsaLevel};
///
/// let seed = mnemonic_to_seed(
///     "abandon abandon abandon abandon abandon abandon \
///      abandon abandon abandon abandon abandon about",
///     ""
/// )?;
///
/// let keypair = derive_keypair(&seed, 0, 0, MlDsaLevel::Dsa44)?;
/// # Ok::<(), ml_dsa_bip39::Error>(())
/// ```
pub fn derive_keypair(
    seed: &[u8; 64],
    account: u32,
    index: u32,
    level: MlDsaLevel,
) -> Result<MlDsaKeyPair> {
    derive_keypair_with_coin(seed, SILICA_COIN_TYPE, account, index, level)
}

/// Derive an ML-DSA keypair with custom coin type
///
/// # Arguments
/// * `seed` - 64-byte BIP39 seed
/// * `coin` - Coin type (e.g., 1337 for Silica)
/// * `account` - Account index
/// * `index` - Key index within the account
/// * `level` - ML-DSA security level
///
/// # Example
/// ```
/// use ml_dsa_bip39::{derive_keypair_with_coin, mnemonic_to_seed, MlDsaLevel};
///
/// let seed = mnemonic_to_seed(
///     "abandon abandon abandon abandon abandon abandon \
///      abandon abandon abandon abandon abandon about",
///     ""
/// )?;
///
/// // Use custom coin type (e.g., 60 for Ethereum-style)
/// let keypair = derive_keypair_with_coin(&seed, 60, 0, 0, MlDsaLevel::Dsa44)?;
/// # Ok::<(), ml_dsa_bip39::Error>(())
/// ```
pub fn derive_keypair_with_coin(
    seed: &[u8; 64],
    coin: u32,
    account: u32,
    index: u32,
    level: MlDsaLevel,
) -> Result<MlDsaKeyPair> {
    // Construct derivation path string
    let path = format!("m/{}'/{}'/{}'/0/{}", level.purpose(), coin, account, index);
    
    // Derive 32-byte ML-DSA seed using SHAKE256
    let ml_dsa_seed = derive_ml_dsa_seed(seed, &path, level);
    
    // Generate keypair using the configured backend
    #[cfg(feature = "rustcrypto")]
    {
        backend_rustcrypto::generate_keypair(level, &ml_dsa_seed)
    }
    
    #[cfg(not(any(feature = "rustcrypto")))]
    {
        Err(Error::UnsupportedLevel(
            "No ML-DSA backend enabled. Enable 'rustcrypto' feature.".to_string()
        ))
    }
}

/// Derive a 32-byte ML-DSA seed from BIP39 seed using SHAKE256
///
/// Domain separation ensures:
/// - Different levels produce different seeds (via domain separator)
/// - Different paths produce different seeds (via path string)
fn derive_ml_dsa_seed(
    bip39_seed: &[u8; 64],
    path: &str,
    level: MlDsaLevel,
) -> [u8; 32] {
    let mut hasher = Shake256::default();
    
    // Domain separation by level
    hasher.update(level.domain_separator());
    
    // Include the BIP39 seed
    hasher.update(bip39_seed);
    
    // Include the derivation path
    hasher.update(path.as_bytes());
    
    // Extract exactly 32 bytes
    let mut ml_dsa_seed = [0u8; 32];
    hasher.finalize_xof().read(&mut ml_dsa_seed);
    
    ml_dsa_seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mnemonic_to_seed_valid() {
        let result = mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about",
            ""
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 64);
    }

    #[test]
    fn test_mnemonic_to_seed_invalid() {
        let result = mnemonic_to_seed("invalid mnemonic words here", "");
        assert!(result.is_err());
    }

    #[test]
    fn test_passphrase_changes_seed() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon abandon abandon about";
        
        let seed1 = mnemonic_to_seed(mnemonic, "").unwrap();
        let seed2 = mnemonic_to_seed(mnemonic, "password").unwrap();
        
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_derive_ml_dsa_seed_determinism() {
        let bip39_seed = [42u8; 64];
        let path = "m/8844'/1337'/0'/0/0";
        
        let seed1 = derive_ml_dsa_seed(&bip39_seed, path, MlDsaLevel::Dsa44);
        let seed2 = derive_ml_dsa_seed(&bip39_seed, path, MlDsaLevel::Dsa44);
        
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_derive_ml_dsa_seed_different_paths() {
        let bip39_seed = [42u8; 64];
        
        let seed1 = derive_ml_dsa_seed(&bip39_seed, "m/8844'/1337'/0'/0/0", MlDsaLevel::Dsa44);
        let seed2 = derive_ml_dsa_seed(&bip39_seed, "m/8844'/1337'/0'/0/1", MlDsaLevel::Dsa44);
        
        assert_ne!(seed1, seed2);
    }

    #[test]
    fn test_derive_ml_dsa_seed_different_levels() {
        let bip39_seed = [42u8; 64];
        let path = "m/8844'/1337'/0'/0/0";
        
        let seed44 = derive_ml_dsa_seed(&bip39_seed, path, MlDsaLevel::Dsa44);
        let seed65 = derive_ml_dsa_seed(&bip39_seed, path, MlDsaLevel::Dsa65);
        
        assert_ne!(seed44, seed65);
    }
}
