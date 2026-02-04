//! RustCrypto ml-dsa backend implementation
//!
//! This module provides the actual ML-DSA cryptographic operations
//! using the `ml-dsa` crate from RustCrypto.

use ml_dsa::{
    MlDsa44, MlDsa65, MlDsa87,
    KeyGen, VerifyingKey, Signature,
    signature::{SignatureEncoding, Signer, Verifier},
};

use crate::{Error, MlDsaKeyPair, MlDsaLevel, MlDsaSignature, Result};

/// Generate an ML-DSA keypair from a 32-byte seed
pub fn generate_keypair(level: MlDsaLevel, seed: &[u8; 32]) -> Result<MlDsaKeyPair> {
    match level {
        MlDsaLevel::Dsa44 => {
            let seed_array: hybrid_array::Array<u8, _> = (*seed).into();
            let keypair = MlDsa44::from_seed(&seed_array);
            let public_key = keypair.verifying_key().encode().to_vec();
            Ok(MlDsaKeyPair::new(level, *seed, public_key))
        }
        MlDsaLevel::Dsa65 => {
            let seed_array: hybrid_array::Array<u8, _> = (*seed).into();
            let keypair = MlDsa65::from_seed(&seed_array);
            let public_key = keypair.verifying_key().encode().to_vec();
            Ok(MlDsaKeyPair::new(level, *seed, public_key))
        }
        MlDsaLevel::Dsa87 => {
            let seed_array: hybrid_array::Array<u8, _> = (*seed).into();
            let keypair = MlDsa87::from_seed(&seed_array);
            let public_key = keypair.verifying_key().encode().to_vec();
            Ok(MlDsaKeyPair::new(level, *seed, public_key))
        }
    }
}

/// Sign a message using the keypair's seed
pub fn sign(keypair: &MlDsaKeyPair, message: &[u8]) -> Result<MlDsaSignature> {
    let seed = keypair.seed();
    
    match keypair.level() {
        MlDsaLevel::Dsa44 => {
            let seed_array: hybrid_array::Array<u8, _> = (*seed).into();
            let kp = MlDsa44::from_seed(&seed_array);
            let signature = kp.signing_key().sign(message);
            Ok(MlDsaSignature::new(keypair.level(), signature.to_bytes().to_vec()))
        }
        MlDsaLevel::Dsa65 => {
            let seed_array: hybrid_array::Array<u8, _> = (*seed).into();
            let kp = MlDsa65::from_seed(&seed_array);
            let signature = kp.signing_key().sign(message);
            Ok(MlDsaSignature::new(keypair.level(), signature.to_bytes().to_vec()))
        }
        MlDsaLevel::Dsa87 => {
            let seed_array: hybrid_array::Array<u8, _> = (*seed).into();
            let kp = MlDsa87::from_seed(&seed_array);
            let signature = kp.signing_key().sign(message);
            Ok(MlDsaSignature::new(keypair.level(), signature.to_bytes().to_vec()))
        }
    }
}

/// Verify a signature against a public key
pub fn verify(
    public_key: &[u8],
    level: MlDsaLevel,
    message: &[u8],
    signature: &MlDsaSignature,
) -> Result<bool> {
    // Ensure signature level matches
    if signature.level() != level {
        return Err(Error::InvalidSignature(format!(
            "signature level {} doesn't match expected level {}",
            signature.level(),
            level
        )));
    }

    match level {
        MlDsaLevel::Dsa44 => {
            let vk_bytes: [u8; 1312] = public_key.try_into()
                .map_err(|_| Error::InvalidPublicKey(format!(
                    "expected {} bytes, got {}",
                    1312,
                    public_key.len()
                )))?;
            let vk = VerifyingKey::<MlDsa44>::decode(&vk_bytes.into());
            
            let sig_bytes: [u8; 2420] = signature.as_bytes().try_into()
                .map_err(|_| Error::InvalidSignature(format!(
                    "expected {} bytes, got {}",
                    2420,
                    signature.as_bytes().len()
                )))?;
            let sig = Signature::<MlDsa44>::decode(&sig_bytes.into())
                .ok_or_else(|| Error::InvalidSignature("failed to decode signature".to_string()))?;
            
            Ok(vk.verify(message, &sig).is_ok())
        }
        MlDsaLevel::Dsa65 => {
            let vk_bytes: [u8; 1952] = public_key.try_into()
                .map_err(|_| Error::InvalidPublicKey(format!(
                    "expected {} bytes, got {}",
                    1952,
                    public_key.len()
                )))?;
            let vk = VerifyingKey::<MlDsa65>::decode(&vk_bytes.into());
            
            let sig_bytes: [u8; 3309] = signature.as_bytes().try_into()
                .map_err(|_| Error::InvalidSignature(format!(
                    "expected {} bytes, got {}",
                    3309,
                    signature.as_bytes().len()
                )))?;
            let sig = Signature::<MlDsa65>::decode(&sig_bytes.into())
                .ok_or_else(|| Error::InvalidSignature("failed to decode signature".to_string()))?;
            
            Ok(vk.verify(message, &sig).is_ok())
        }
        MlDsaLevel::Dsa87 => {
            let vk_bytes: [u8; 2592] = public_key.try_into()
                .map_err(|_| Error::InvalidPublicKey(format!(
                    "expected {} bytes, got {}",
                    2592,
                    public_key.len()
                )))?;
            let vk = VerifyingKey::<MlDsa87>::decode(&vk_bytes.into());
            
            let sig_bytes: [u8; 4627] = signature.as_bytes().try_into()
                .map_err(|_| Error::InvalidSignature(format!(
                    "expected {} bytes, got {}",
                    4627,
                    signature.as_bytes().len()
                )))?;
            let sig = Signature::<MlDsa87>::decode(&sig_bytes.into())
                .ok_or_else(|| Error::InvalidSignature("failed to decode signature".to_string()))?;
            
            Ok(vk.verify(message, &sig).is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_keypair_dsa44() {
        let seed = [42u8; 32];
        let keypair = generate_keypair(MlDsaLevel::Dsa44, &seed).unwrap();
        
        assert_eq!(keypair.level(), MlDsaLevel::Dsa44);
        assert_eq!(keypair.public_key().len(), 1312);
    }

    #[test]
    fn test_generate_keypair_dsa65() {
        let seed = [42u8; 32];
        let keypair = generate_keypair(MlDsaLevel::Dsa65, &seed).unwrap();
        
        assert_eq!(keypair.level(), MlDsaLevel::Dsa65);
        assert_eq!(keypair.public_key().len(), 1952);
    }

    #[test]
    fn test_generate_keypair_dsa87() {
        let seed = [42u8; 32];
        let keypair = generate_keypair(MlDsaLevel::Dsa87, &seed).unwrap();
        
        assert_eq!(keypair.level(), MlDsaLevel::Dsa87);
        assert_eq!(keypair.public_key().len(), 2592);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let seed = [42u8; 32];
        let keypair = generate_keypair(MlDsaLevel::Dsa44, &seed).unwrap();
        
        let message = b"test message for signing";
        let signature = sign(&keypair, message).unwrap();
        
        let valid = verify(
            keypair.public_key(),
            keypair.level(),
            message,
            &signature
        ).unwrap();
        
        assert!(valid);
    }

    #[test]
    fn test_verify_wrong_message_fails() {
        let seed = [42u8; 32];
        let keypair = generate_keypair(MlDsaLevel::Dsa44, &seed).unwrap();
        
        let message = b"original message";
        let signature = sign(&keypair, message).unwrap();
        
        let valid = verify(
            keypair.public_key(),
            keypair.level(),
            b"different message",
            &signature
        ).unwrap();
        
        assert!(!valid);
    }

    #[test]
    fn test_deterministic_keygen() {
        let seed = [42u8; 32];
        
        let kp1 = generate_keypair(MlDsaLevel::Dsa44, &seed).unwrap();
        let kp2 = generate_keypair(MlDsaLevel::Dsa44, &seed).unwrap();
        
        assert_eq!(kp1.public_key(), kp2.public_key());
    }
}
