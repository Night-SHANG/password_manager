use argon2::{Algorithm, Argon2, Block, Params as Argon2Params, Version};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

    let mut scratch = Argon2Scratch::new(params.block_count())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    argon2
        .hash_password_into_with_memory(
            master_password.as_bytes(),
            salt,
            &mut scratch.output[..],
            scratch.memory.as_mut_slice(),
        )
        .map_err(|_| AppError::Crypto("Argon2id derivation failed"))?;
    #[cfg(test)]
    tests::after_hash()?;
    Ok(*scratch.output)
}

/// Owns the caller-supplied Argon2 state and temporary output for the entire call.
/// The returned KEK remains the caller's responsibility, as before.
struct Argon2Scratch {
    memory: Zeroizing<Vec<Block>>,
    output: Zeroizing<[u8; KEY_LEN]>,
}

impl Argon2Scratch {
    fn new(block_count: usize) -> Result<Self> {
        let mut scratch = Self {
            memory: Zeroizing::new(Vec::new()),
            output: Zeroizing::new([0u8; KEY_LEN]),
        };
        // Vec allocations must fit both checked byte accounting and isize::MAX.
        // This admits the full existing 1 GiB KDF range on supported platforms.
        block_count
            .checked_mul(std::mem::size_of::<Block>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .ok_or(AppError::Crypto(
                "Argon2id working memory allocation failed",
            ))?;
        // Exercise the real try_reserve_exact error mapping with a guaranteed
        // capacity-overflow request in tests, rather than exhausting the host.
        #[cfg(test)]
        let reserve_count = if tests::allocation_should_fail() {
            usize::MAX
        } else {
            block_count
        };
        #[cfg(not(test))]
        let reserve_count = block_count;
        scratch
            .memory
            .try_reserve_exact(reserve_count)
            .map_err(|_| AppError::Crypto("Argon2id working memory allocation failed"))?;
        // Reservation precedes initialization, so this cannot reallocate. Only
        // one 1 KiB Block is initialized at a time; no large stack array is used.
        scratch.memory.resize_with(block_count, Block::new);
        Ok(scratch)
    }
}

impl Drop for Argon2Scratch {
    fn drop(&mut self) {
        #[cfg(test)]
        let populated = tests::populated_buffers(&self.memory, &self.output);
        // Keep the initialized live slice available for the cleanup probe.
        // The Zeroizing fields subsequently wipe their full capacity on drop.
        for block in self.memory.iter_mut() {
            block.zeroize();
        }
        self.output.zeroize();
        #[cfg(test)]
        tests::observe_wiped_buffers(&self.memory, &self.output, populated);
    }
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
    use std::cell::Cell;

    use super::*;

    thread_local! {
        static FAIL_WORKING_MEMORY_ALLOCATION: Cell<bool> = const { Cell::new(false) };
        static AFTER_HASH_ACTION: Cell<AfterHashAction> = const { Cell::new(AfterHashAction::Continue) };
        static WIPE_OBSERVATION: Cell<Option<WipeObservation>> = const { Cell::new(None) };
    }

    #[derive(Clone, Copy)]
    enum AfterHashAction {
        Continue,
        Error,
        Unwind,
    }

    #[derive(Clone, Copy)]
    struct WipeObservation {
        blocks: usize,
        memory_was_populated: bool,
        output_was_populated: bool,
        memory_is_zero: bool,
        output_is_zero: bool,
    }

    struct ResetDerivationHooks;

    impl Drop for ResetDerivationHooks {
        fn drop(&mut self) {
            FAIL_WORKING_MEMORY_ALLOCATION.set(false);
            AFTER_HASH_ACTION.set(AfterHashAction::Continue);
            WIPE_OBSERVATION.set(None);
        }
    }

    pub(super) fn allocation_should_fail() -> bool {
        FAIL_WORKING_MEMORY_ALLOCATION.get()
    }

    pub(super) fn after_hash() -> Result<()> {
        match AFTER_HASH_ACTION.get() {
            AfterHashAction::Continue => Ok(()),
            AfterHashAction::Error => Err(AppError::Crypto("synthetic post-derivation failure")),
            AfterHashAction::Unwind => panic!("synthetic post-derivation unwind"),
        }
    }

    pub(super) fn populated_buffers(memory: &[Block], output: &[u8; KEY_LEN]) -> (bool, bool) {
        (
            memory
                .iter()
                .any(|block| block.as_ref().iter().any(|word| *word != 0)),
            output.iter().any(|byte| *byte != 0),
        )
    }

    pub(super) fn observe_wiped_buffers(
        memory: &[Block],
        output: &[u8; KEY_LEN],
        populated: (bool, bool),
    ) {
        // Inspect only the live initialized allocation, before any deallocation.
        // Store nonsecret observations without allocating or asserting in Drop.
        WIPE_OBSERVATION.set(Some(WipeObservation {
            blocks: memory.len(),
            memory_was_populated: populated.0,
            output_was_populated: populated.1,
            memory_is_zero: memory
                .iter()
                .all(|block| block.as_ref().iter().all(|word| *word == 0)),
            output_is_zero: output.iter().all(|byte| *byte == 0),
        }));
    }

    fn inexpensive_config() -> KdfConfig {
        KdfConfig {
            memory_kib: MIN_MEMORY_KIB,
            iterations: MIN_ITERATIONS,
            parallelism: MIN_PARALLELISM,
        }
    }

    fn assert_populated_buffers_were_wiped() {
        let observation = WIPE_OBSERVATION
            .get()
            .expect("the working-memory owner must report cleanup before deallocation");
        assert_eq!(observation.blocks, MIN_MEMORY_KIB as usize);
        assert!(observation.memory_was_populated);
        assert!(observation.output_was_populated);
        assert!(observation.memory_is_zero);
        assert!(observation.output_is_zero);
    }

    #[test]
    fn derive_kek_returns_error_on_working_memory_allocation_failure() {
        let _reset = ResetDerivationHooks;
        FAIL_WORKING_MEMORY_ALLOCATION.set(true);
        let result = derive_kek(
            "synthetic allocation failure fixture",
            &[0x19; SALT_LEN],
            inexpensive_config(),
        );
        assert!(matches!(
            result,
            Err(AppError::Crypto(
                "Argon2id working memory allocation failed"
            ))
        ));
    }

    #[test]
    fn derive_kek_wipes_live_working_memory_and_output_on_success() {
        let _reset = ResetDerivationHooks;
        derive_kek(
            "synthetic success fixture",
            &[0x21; SALT_LEN],
            inexpensive_config(),
        )
        .unwrap();
        assert_populated_buffers_were_wiped();
    }

    #[test]
    fn derive_kek_wipes_live_working_memory_and_output_on_error() {
        let _reset = ResetDerivationHooks;
        AFTER_HASH_ACTION.set(AfterHashAction::Error);
        assert!(
            derive_kek(
                "synthetic error fixture",
                &[0x22; SALT_LEN],
                inexpensive_config()
            )
            .is_err()
        );
        assert_populated_buffers_were_wiped();
    }

    #[test]
    fn derive_kek_wipes_live_working_memory_and_output_on_unwind() {
        let _reset = ResetDerivationHooks;
        AFTER_HASH_ACTION.set(AfterHashAction::Unwind);
        let result = std::panic::catch_unwind(|| {
            let _ = derive_kek(
                "synthetic unwind fixture",
                &[0x23; SALT_LEN],
                inexpensive_config(),
            );
        });
        assert!(result.is_err());
        assert_populated_buffers_were_wiped();
    }

    #[test]
    fn argon2_scratch_wipes_populated_buffers_on_library_error() {
        let _reset = ResetDerivationHooks;
        let result = (|| -> Result<()> {
            let config = inexpensive_config();
            let params = Argon2Params::new(
                config.memory_kib,
                config.iterations,
                config.parallelism,
                Some(KEY_LEN),
            )
            .unwrap();
            let mut scratch = Argon2Scratch::new(params.block_count())?;
            scratch.memory[0].as_mut()[0] = 0x71;
            scratch.output[0] = 0x72;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            argon2
                .hash_password_into_with_memory(
                    b"synthetic rejected-output fixture",
                    &[0x26; SALT_LEN],
                    &mut scratch.output[..KEY_LEN - 1],
                    scratch.memory.as_mut_slice(),
                )
                .map_err(|_| AppError::Crypto("Argon2id derivation failed"))
        })();
        assert!(matches!(
            result,
            Err(AppError::Crypto("Argon2id derivation failed"))
        ));
        assert_populated_buffers_were_wiped();
    }

    #[test]
    fn argon2_scratch_rejects_overflowing_byte_accounting_without_panicking() {
        let _reset = ResetDerivationHooks;
        for block_count in [
            usize::MAX,
            isize::MAX as usize / std::mem::size_of::<Block>() + 1,
        ] {
            assert!(matches!(
                Argon2Scratch::new(block_count),
                Err(AppError::Crypto(
                    "Argon2id working memory allocation failed"
                ))
            ));
        }
    }

    #[test]
    fn derive_kek_preserves_deterministic_argon2_output() {
        let _reset = ResetDerivationHooks;
        for config in [
            inexpensive_config(),
            KdfConfig {
                memory_kib: MIN_MEMORY_KIB + 5,
                iterations: 2,
                parallelism: 3,
            },
        ] {
            let params = Argon2Params::new(
                config.memory_kib,
                config.iterations,
                config.parallelism,
                Some(KEY_LEN),
            )
            .unwrap();
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut expected = [0u8; KEY_LEN];
            argon2
                .hash_password_into(
                    b"synthetic compatibility fixture",
                    &[0x24; SALT_LEN],
                    &mut expected,
                )
                .unwrap();
            assert_eq!(
                derive_kek("synthetic compatibility fixture", &[0x24; SALT_LEN], config).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn derive_kek_allocates_exact_effective_argon2_block_count() {
        let _reset = ResetDerivationHooks;
        let config = KdfConfig {
            memory_kib: MIN_MEMORY_KIB + 5,
            iterations: 1,
            parallelism: 3,
        };
        let params = Argon2Params::new(
            config.memory_kib,
            config.iterations,
            config.parallelism,
            Some(KEY_LEN),
        )
        .unwrap();
        assert_ne!(params.block_count(), config.memory_kib as usize);
        derive_kek("synthetic aligned block fixture", &[0x25; SALT_LEN], config).unwrap();
        assert_eq!(
            WIPE_OBSERVATION
                .get()
                .expect("working-memory cleanup observation")
                .blocks,
            params.block_count(),
        );
    }

    #[test]
    fn kdf_preserves_defaults_and_all_accepted_bounds() {
        let _reset = ResetDerivationHooks;
        FAIL_WORKING_MEMORY_ALLOCATION.set(true);
        assert_eq!(
            KdfConfig::default(),
            KdfConfig {
                memory_kib: 64 * 1024,
                iterations: 3,
                parallelism: 1,
            }
        );
        for memory_kib in [
            MIN_MEMORY_KIB,
            MIN_MEMORY_KIB + 1,
            MAX_MEMORY_KIB - 1,
            MAX_MEMORY_KIB,
        ] {
            for iterations in MIN_ITERATIONS..=MAX_ITERATIONS {
                for parallelism in MIN_PARALLELISM..=MAX_PARALLELISM {
                    let config = KdfConfig {
                        memory_kib,
                        iterations,
                        parallelism,
                    };
                    assert_eq!(config.validate().unwrap(), config);
                    let params =
                        Argon2Params::new(memory_kib, iterations, parallelism, Some(KEY_LEN))
                            .unwrap();
                    assert!(params.block_count() <= memory_kib as usize);
                    // Even the 1 GiB/10-pass/16-lane accepted corner reaches the
                    // allocation seam, without allocating or hashing that size.
                    assert!(matches!(
                        derive_kek(
                            "synthetic accepted-bound fixture",
                            &[0x27; SALT_LEN],
                            config
                        ),
                        Err(AppError::Crypto(
                            "Argon2id working memory allocation failed"
                        ))
                    ));
                }
            }
        }
        for config in [
            KdfConfig {
                memory_kib: MIN_MEMORY_KIB - 1,
                ..KdfConfig::default()
            },
            KdfConfig {
                memory_kib: MAX_MEMORY_KIB + 1,
                ..KdfConfig::default()
            },
            KdfConfig {
                iterations: MIN_ITERATIONS - 1,
                ..KdfConfig::default()
            },
            KdfConfig {
                iterations: MAX_ITERATIONS + 1,
                ..KdfConfig::default()
            },
            KdfConfig {
                parallelism: MIN_PARALLELISM - 1,
                ..KdfConfig::default()
            },
            KdfConfig {
                parallelism: MAX_PARALLELISM + 1,
                ..KdfConfig::default()
            },
        ] {
            assert!(matches!(config.validate(), Err(AppError::InvalidKdf)));
        }
    }

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
