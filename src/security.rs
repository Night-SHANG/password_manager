use argon2::{Algorithm, Argon2, Params as Argon2Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AppError, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;

const MIN_MEMORY_KIB: u32 = 8 * 1024;
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MIN_ITERATIONS: u32 = 1;
const MAX_ITERATIONS: u32 = 10;
const MIN_PARALLELISM: u32 = 1;
const MAX_PARALLELISM: u32 = 16;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfConfig {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfConfig {
    pub fn validate(self) -> Result<Self> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations)
            || !(MIN_PARALLELISM..=MAX_PARALLELISM).contains(&self.parallelism)
        {
            return Err(AppError::InvalidKdf);
        }
        Ok(self)
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct VaultKeys {
    pub vault_key: [u8; KEY_LEN],
    pub secret_key: [u8; KEY_LEN],
}

impl VaultKeys {
    pub fn from_vault_key(vault_key: [u8; KEY_LEN]) -> Result<Self> {
        let secret_key = derive_subkey(&vault_key, b"password-manager/entry-secret/v1")?;
        Ok(Self {
            vault_key,
            secret_key,
        })
    }
}

pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| AppError::Crypto("OS random generator failed"))?;
    Ok(out)
}

pub fn derive_kek(master_password: &str, salt: &[u8], config: KdfConfig) -> Result<[u8; KEY_LEN]> {
    let config = config.validate()?;
    if salt.len() < SALT_LEN {
        return Err(AppError::InvalidVault("KDF salt is too short"));
    }

    let params = Argon2Params::new(
        config.memory_kib,
        config.iterations,
        config.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|_| AppError::InvalidKdf)?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; KEY_LEN];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut out)
        .map_err(|_| AppError::Crypto("Argon2id derivation failed"))?;
    Ok(out)
}

pub fn derive_subkey(root_key: &[u8; KEY_LEN], domain: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, root_key);
    let mut out = [0u8; KEY_LEN];
    hk.expand(domain, &mut out)
        .map_err(|_| AppError::Crypto("HKDF expansion failed"))?;
    Ok(out)
}

pub fn seal(
    key_bytes: &[u8; KEY_LEN],
    nonce_bytes: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let key: &Key = key_bytes.into();
    let nonce: &XNonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new(key);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| AppError::Crypto("XChaCha20-Poly1305 encryption failed"))
}

pub fn open(
    key_bytes: &[u8; KEY_LEN],
    nonce_bytes: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let key: &Key = key_bytes.into();
    let nonce: &XNonce = nonce_bytes.into();
    let cipher = XChaCha20Poly1305::new(key);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| AppError::Crypto("authentication failed"))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn wipe<const N: usize>(bytes: &mut [u8; N]) {
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_bounds_reject_extreme_values() {
        assert!(
            KdfConfig {
                memory_kib: MAX_MEMORY_KIB + 1,
                ..KdfConfig::default()
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn aead_rejects_tampering() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let mut ciphertext = seal(&key, &nonce, b"aad", b"secret").unwrap();
        ciphertext[0] ^= 0x80;
        assert!(open(&key, &nonce, b"aad", &ciphertext).is_err());
    }
}
