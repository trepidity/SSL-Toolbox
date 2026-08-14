//! Passphrase-sealed storage for small secrets.
//!
//! A generic authenticated-encryption envelope: bytes in, a [`SealedBlob`] out,
//! recoverable only with the passphrase that sealed it. It knows nothing about
//! what it protects — `ssl-toolbox-ops` decides that (CA client credentials
//! today) and owns where the blob lands on disk.
//!
//! ## Construction
//!
//! - **KDF** — scrypt, `N = 32768, r = 8, p = 1` (32 MiB), producing a 256-bit
//!   key. Memory-hard, so a stolen vault file does not fall to a GPU wordlist
//!   the way a PBKDF2 file would.
//! - **Cipher** — AES-256-GCM with a 96-bit random nonce, the standard size for
//!   GCM's counter construction.
//! - **AAD** — the version tag and the KDF parameters, authenticated but not
//!   encrypted. An attacker who rewrites `n` down to 1 to make cracking cheap
//!   invalidates the tag, so weakening the file is detected as tampering rather
//!   than silently honored on the next open.
//!
//! Both primitives come from the OpenSSL already vendored for certificate work
//! (ARCHITECTURE.md §11.4) — no second crypto stack enters the build.
//!
//! ## What this does and does not buy
//!
//! It protects the credential at rest: a backup, a synced home directory, or a
//! stolen disk yields ciphertext. It does **not** protect against a compromised
//! host — anything that can read the process while it holds the derived key can
//! read the plaintext (ARCHITECTURE.md §11.2). The passphrase is the only
//! custodian; there is no recovery path if it is lost.

use anyhow::{Context, Result, anyhow};
use openssl::base64;
use openssl::pkcs5::scrypt;
use openssl::rand::rand_bytes;
use openssl::symm::{Cipher, Crypter, Mode};
use serde::{Deserialize, Serialize};

/// Envelope format version. Bump only for a breaking layout change, and teach
/// [`open`] to read the old value — a vault the user cannot open is data loss.
const VERSION: u8 = 1;

const SCRYPT_N: u64 = 32_768;
const SCRYPT_R: u64 = 8;
const SCRYPT_P: u64 = 1;
/// scrypt at the parameters above needs `128 * N * r` bytes (32 MiB). OpenSSL
/// refuses to exceed `maxmem`, so this is set above the requirement with room
/// for the allocator rather than exactly at it.
const SCRYPT_MAXMEM: u64 = 64 * 1024 * 1024;

const KEY_LEN: usize = 32;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// A sealed secret, safe to write to disk.
///
/// Serializes to JSON so a vault file stays inspectable — an operator can see
/// the KDF parameters and confirm the payload is ciphertext without running the
/// tool. Every binary field is base64.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedBlob {
    pub version: u8,
    /// Named so a future migration to a different KDF can be detected on read
    /// rather than mis-parsed.
    pub kdf: String,
    pub scrypt_n: u64,
    pub scrypt_r: u64,
    pub scrypt_p: u64,
    pub salt: String,
    pub nonce: String,
    pub tag: String,
    pub ciphertext: String,
}

/// Bind the version and KDF parameters into the GCM tag.
fn aad(version: u8, n: u64, r: u64, p: u64) -> Vec<u8> {
    format!("ssl-toolbox-vault|v{version}|scrypt|{n}|{r}|{p}").into_bytes()
}

fn derive_key(passphrase: &str, salt: &[u8], n: u64, r: u64, p: u64) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    scrypt(
        passphrase.as_bytes(),
        salt,
        n,
        r,
        p,
        SCRYPT_MAXMEM,
        &mut key,
    )
    .context("Failed to derive a key from the passphrase")?;
    Ok(key)
}

/// Encrypt `plaintext` under `passphrase`.
///
/// A fresh salt and nonce are drawn per call, so sealing the same secret twice
/// produces two unrelated blobs and reveals nothing by comparison.
pub fn seal(plaintext: &[u8], passphrase: &str) -> Result<SealedBlob> {
    if passphrase.is_empty() {
        return Err(anyhow!("A vault passphrase is required"));
    }

    let mut salt = [0u8; SALT_LEN];
    rand_bytes(&mut salt).context("Failed to generate a vault salt")?;
    let mut nonce = [0u8; NONCE_LEN];
    rand_bytes(&mut nonce).context("Failed to generate a vault nonce")?;

    let key = derive_key(passphrase, &salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)?;
    let associated = aad(VERSION, SCRYPT_N, SCRYPT_R, SCRYPT_P);

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, &key, Some(&nonce))
        .context("Failed to initialise the vault cipher")?;
    crypter
        .aad_update(&associated)
        .context("Failed to authenticate the vault header")?;

    let mut ciphertext = vec![0u8; plaintext.len() + cipher.block_size()];
    let mut written = crypter
        .update(plaintext, &mut ciphertext)
        .context("Failed to encrypt the vault payload")?;
    written += crypter
        .finalize(&mut ciphertext[written..])
        .context("Failed to finalise the vault payload")?;
    ciphertext.truncate(written);

    let mut tag = [0u8; TAG_LEN];
    crypter
        .get_tag(&mut tag)
        .context("Failed to read the vault authentication tag")?;

    Ok(SealedBlob {
        version: VERSION,
        kdf: "scrypt".to_string(),
        scrypt_n: SCRYPT_N,
        scrypt_r: SCRYPT_R,
        scrypt_p: SCRYPT_P,
        salt: base64::encode_block(&salt),
        nonce: base64::encode_block(&nonce),
        tag: base64::encode_block(&tag),
        ciphertext: base64::encode_block(&ciphertext),
    })
}

/// Recover the plaintext sealed by [`seal`].
///
/// Returns [`VaultError::WrongPassphrase`] for both a bad passphrase and a
/// modified file: GCM cannot tell the two apart, and guessing on the user's
/// behalf would be a lie in one of the two cases.
pub fn open(blob: &SealedBlob, passphrase: &str) -> Result<Vec<u8>, VaultError> {
    if blob.version != VERSION {
        return Err(VaultError::UnsupportedVersion(blob.version));
    }
    if blob.kdf != "scrypt" {
        return Err(VaultError::UnsupportedKdf(blob.kdf.clone()));
    }

    let salt = decode(&blob.salt, "salt")?;
    let nonce = decode(&blob.nonce, "nonce")?;
    let tag = decode(&blob.tag, "tag")?;
    let ciphertext = decode(&blob.ciphertext, "ciphertext")?;

    let key = derive_key(
        passphrase,
        &salt,
        blob.scrypt_n,
        blob.scrypt_r,
        blob.scrypt_p,
    )
    .map_err(|error| VaultError::Malformed(error.to_string()))?;
    let associated = aad(blob.version, blob.scrypt_n, blob.scrypt_r, blob.scrypt_p);

    let cipher = Cipher::aes_256_gcm();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, &key, Some(&nonce))
        .map_err(|error| VaultError::Malformed(error.to_string()))?;
    crypter
        .aad_update(&associated)
        .map_err(|error| VaultError::Malformed(error.to_string()))?;
    crypter
        .set_tag(&tag)
        .map_err(|error| VaultError::Malformed(error.to_string()))?;

    let mut plaintext = vec![0u8; ciphertext.len() + cipher.block_size()];
    let mut written = crypter
        .update(&ciphertext, &mut plaintext)
        .map_err(|error| VaultError::Malformed(error.to_string()))?;

    // A tag mismatch surfaces here, not at `update` — this is the wrong-passphrase path.
    match crypter.finalize(&mut plaintext[written..]) {
        Ok(extra) => written += extra,
        Err(_) => return Err(VaultError::WrongPassphrase),
    }

    plaintext.truncate(written);
    Ok(plaintext)
}

fn decode(value: &str, field: &str) -> Result<Vec<u8>, VaultError> {
    base64::decode_block(value)
        .map_err(|_| VaultError::Malformed(format!("vault field '{field}' is not valid base64")))
}

/// Why a vault could not be opened.
///
/// Separated from `anyhow` so a caller can distinguish "the user typed the
/// wrong passphrase" — worth re-prompting for — from "this file is not a vault",
/// which re-prompting will never fix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    WrongPassphrase,
    UnsupportedVersion(u8),
    UnsupportedKdf(String),
    Malformed(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassphrase => f.write_str(
                "Incorrect vault passphrase, or the vault file has been modified since it was written",
            ),
            Self::UnsupportedVersion(version) => write!(
                f,
                "Vault format version {version} is not supported by this build"
            ),
            Self::UnsupportedKdf(kdf) => {
                write!(f, "Vault key derivation '{kdf}' is not supported")
            }
            Self::Malformed(detail) => write!(f, "Vault file is malformed: {detail}"),
        }
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_secret_round_trips_through_the_correct_passphrase() {
        let sealed = seal(b"client-secret-value", "correct horse battery").expect("seal");
        let opened = open(&sealed, "correct horse battery").expect("open");
        assert_eq!(opened, b"client-secret-value");
    }

    #[test]
    fn wrong_passphrase_is_rejected_rather_than_returning_garbage() {
        let sealed = seal(b"client-secret-value", "correct horse battery").expect("seal");
        assert_eq!(
            open(&sealed, "wrong passphrase"),
            Err(VaultError::WrongPassphrase)
        );
    }

    #[test]
    fn sealed_form_does_not_contain_the_plaintext() {
        // The point of the file: a stolen copy must not spell out the secret.
        let sealed = seal(b"SUPER-SECRET-CLIENT-KEY", "vault passphrase").expect("seal");
        let json = serde_json::to_string(&sealed).expect("serialize");
        assert!(!json.contains("SUPER-SECRET-CLIENT-KEY"));
        assert!(!json.contains("vault passphrase"));
    }

    #[test]
    fn tampering_with_the_ciphertext_is_detected() {
        let mut sealed = seal(b"client-secret-value", "vault passphrase").expect("seal");
        let mut raw = base64::decode_block(&sealed.ciphertext).expect("decode");
        raw[0] ^= 0xff;
        sealed.ciphertext = base64::encode_block(&raw);

        assert_eq!(
            open(&sealed, "vault passphrase"),
            Err(VaultError::WrongPassphrase)
        );
    }

    #[test]
    fn weakening_the_kdf_parameters_invalidates_the_blob() {
        // The attack this defends: rewrite N down so the file can be brute
        // forced cheaply, then wait for the tool to re-derive at the weak cost.
        let mut sealed = seal(b"client-secret-value", "vault passphrase").expect("seal");
        sealed.scrypt_n = 2;

        assert_eq!(
            open(&sealed, "vault passphrase"),
            Err(VaultError::WrongPassphrase)
        );
    }

    #[test]
    fn resealing_the_same_secret_produces_a_different_blob() {
        let first = seal(b"same-secret", "same passphrase").expect("seal");
        let second = seal(b"same-secret", "same passphrase").expect("seal");
        assert_ne!(first.ciphertext, second.ciphertext);
        assert_ne!(first.salt, second.salt);
    }

    #[test]
    fn sealing_without_a_passphrase_is_refused() {
        // Otherwise an empty prompt would produce a file that looks encrypted
        // and is trivially openable.
        assert!(seal(b"client-secret-value", "").is_err());
    }
}
