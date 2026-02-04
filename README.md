# ml-dsa-bip39

[![Crates.io](https://img.shields.io/crates/v/ml-dsa-bip39.svg)](https://crates.io/crates/ml-dsa-bip39)
[![Documentation](https://docs.rs/ml-dsa-bip39/badge.svg)](https://docs.rs/ml-dsa-bip39)
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)

BIP39 mnemonic derivation for **ML-DSA** (FIPS 204) post-quantum digital signatures.

Derive deterministic post-quantum keypairs from standard 24-word seed phrases.

## Features

- 🔐 **Deterministic**: Same mnemonic + passphrase always produces same keys
- 🌐 **Portable**: Recover keys on any device with just your seed phrase
- 📊 **Multi-level**: Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87
- 🔀 **Backend-agnostic**: Abstract API allows swapping crypto implementations
- 🛡️ **Secure**: Domain separation prevents cross-level/cross-path collisions

## Quick Start

```rust
use ml_dsa_bip39::{MlDsaLevel, derive_keypair, mnemonic_to_seed};

fn main() -> ml_dsa_bip39::Result<()> {
    // Generate seed from 24-word mnemonic
    let mnemonic = "abandon abandon abandon abandon abandon abandon \
                    abandon abandon abandon abandon abandon about";
    let seed = mnemonic_to_seed(mnemonic, "")?;

    // Derive ML-DSA-44 keypair (128-bit security, default)
    let keypair = derive_keypair(&seed, 0, 0, MlDsaLevel::default())?;

    // Sign and verify
    let message = b"Hello, post-quantum world!";
    let signature = keypair.sign(message)?;
    assert!(keypair.verify(message, &signature)?);
    
    println!("Public key: {} bytes", keypair.public_key().len());
    println!("Signature:  {} bytes", signature.as_bytes().len());
    
    Ok(())
}
```

## Security Levels

| Level | NIST Category | Security | Public Key | Signature | Use Case |
|-------|---------------|----------|------------|-----------|----------|
| **ML-DSA-44** | 2 | 128-bit | 1,312 B | 2,420 B | Default for users |
| **ML-DSA-65** | 3 | 192-bit | 1,952 B | 3,309 B | High-value accounts |
| **ML-DSA-87** | 5 | 256-bit | 2,592 B | 4,627 B | Critical infrastructure |

## Derivation Paths

Each security level uses a unique BIP44-style purpose field:

```
ML-DSA-44: m/8844'/coin'/account'/0/index
ML-DSA-65: m/8865'/coin'/account'/0/index
ML-DSA-87: m/8887'/coin'/account'/0/index
```

This ensures:
- Same mnemonic → different keys per level (by design)
- No collision between Ed25519 (m/44') and ML-DSA paths

## How It Works

```
24-word mnemonic + optional passphrase
       ↓
PBKDF2(mnemonic, "mnemonic" + passphrase, 2048, SHA512)
       ↓
BIP39 Seed (512 bits)
       ↓
SHAKE256(domain_separator || seed || derivation_path)
       ↓
ML-DSA Seed (32 bytes)
       ↓
Deterministic ML-DSA keypair
```

**Domain separation** ensures that:
- Different security levels produce different seeds
- Different derivation paths produce different seeds
- Keys are fully reproducible from mnemonic alone

## Passphrase Support

The optional BIP39 passphrase provides additional security:

```rust
// No passphrase (standard)
let seed1 = mnemonic_to_seed(&mnemonic, "")?;

// With passphrase (completely different keys!)
let seed2 = mnemonic_to_seed(&mnemonic, "my-secret-phrase")?;

assert_ne!(seed1, seed2);
```

## Backend Abstraction

This crate uses an abstract API that doesn't expose implementation details:

```rust
pub struct MlDsaKeyPair {
    level: MlDsaLevel,
    seed: [u8; 32],       // 32-byte seed (compact!)
    public_key: Vec<u8>,  // Level-specific size
}
```

The default backend uses RustCrypto's `ml-dsa` crate. Alternative backends
can be added via feature flags without changing the public API.

## Installation

```toml
[dependencies]
ml-dsa-bip39 = "0.1"
```

## Compatibility

- **ML-DSA (FIPS 204)**: Signatures are compatible with any FIPS 204 implementation
- **BIP39**: Standard mnemonic format, compatible with hardware wallets (for seed generation)
- **Cross-platform**: Pure Rust, works on any platform

## Security Considerations

1. **Mnemonic security**: Store your 24 words safely. They derive ALL your keys.
2. **Passphrase**: Use a strong passphrase for high-value accounts.
3. **Determinism**: No random entropy after derivation - fully reproducible.
4. **Domain separation**: Each level/path produces cryptographically independent keys.

## License

Licensed under either of:
- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
