//! # badkeys-rs
//!
//! Check P256 public keys against a database of known-bad keys sourced from
//! the [badkeys project](https://github.com/badkeys/badkeys).
//!
//! The database is embedded at compile time, so lookups require no I/O.
//! Detection uses a truncated SHA-256 hash of the key's x-coordinate
//! (BKHASH120), with O(log n) binary search.
//!
//! # Example
//!
//! ```no_run
//! use p256::PublicKey;
//!
//! # fn example(key: &PublicKey) {
//! if let Some(info) = badkeys_rs::check_pubkey(key) {
//!     println!("BAD KEY detected! Category: {}", info.category.name());
//! }
//! # }
//! ```

mod category;
mod db;
mod error;
mod extract;

pub use category::Category;
pub use db::BadKeyInfo;
pub use error::Error;

use p256::PublicKey;

/// Check a `p256::PublicKey` against the database of known-bad keys.
///
/// Returns `Some(BadKeyInfo)` if the key is known-bad, `None` otherwise.
pub fn check_pubkey(key: &PublicKey) -> Option<BadKeyInfo> {
    let x = extract::x_bytes_from_pubkey(key);
    let hash = db::bkhash120(&x);
    db::lookup(&hash)
}

/// Check raw x-coordinate bytes (big-endian, up to 32 bytes) against the database.
///
/// Leading zero bytes are stripped before hashing to match the badkeys convention.
pub fn check_x_bytes(x_bytes: &[u8]) -> Option<BadKeyInfo> {
    let hash = db::bkhash120(x_bytes);
    db::lookup(&hash)
}

/// Check a PEM-encoded public key or private key against the database.
///
/// Accepts SubjectPublicKeyInfo PEM, PKCS#8 private key PEM, or SEC1 EC
/// private key PEM. Returns `Err` if the data cannot be parsed as a P256 key.
pub fn check_pem_key(pem_data: &[u8]) -> Result<Option<BadKeyInfo>, Error> {
    let key = extract::pubkey_from_pem(pem_data)?;
    Ok(check_pubkey(&key))
}

/// Check a DER-encoded SubjectPublicKeyInfo against the database.
///
/// Returns `Err` if the DER data cannot be parsed as a P256 key.
pub fn check_der_pubkey(der_data: &[u8]) -> Result<Option<BadKeyInfo>, Error> {
    let key = extract::pubkey_from_spki_der(der_data)?;
    Ok(check_pubkey(&key))
}

/// Check a PEM or DER-encoded X.509 certificate against the database.
///
/// Extracts the public key from the certificate and checks it.
/// Returns `Err` if the certificate cannot be parsed or does not contain a P256 key.
pub fn check_certificate(cert_data: &[u8]) -> Result<Option<BadKeyInfo>, Error> {
    let key = extract::pubkey_from_certificate(cert_data)?;
    Ok(check_pubkey(&key))
}

/// Returns the number of entries in the embedded database.
pub fn database_entry_count() -> usize {
    db::entry_count()
}
