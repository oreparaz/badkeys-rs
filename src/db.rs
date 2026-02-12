use sha2::{Digest, Sha256};

use crate::category::Category;

/// The embedded binary database of known-bad P256 key hashes.
const DB: &[u8] = include_bytes!("../data/p256_blocklist.bin");

/// Size of each record: 15-byte hash + 1-byte category ID.
const RECORD_SIZE: usize = 16;

/// Size of the truncated SHA-256 hash (BKHASH120 = 120 bits = 15 bytes).
pub(crate) const HASH_SIZE: usize = 15;

/// Information about a detected bad key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BadKeyInfo {
    /// The category indicating the source/reason this key is compromised.
    pub category: Category,
}

/// Compute the BKHASH120 from raw x-coordinate bytes (big-endian, possibly with leading zeros).
///
/// Strips leading zero bytes to produce minimum-length big-endian encoding,
/// matching the Python convention: `x.to_bytes((x.bit_length() + 7) // 8, byteorder="big")`.
/// Then computes SHA-256 and truncates to 15 bytes.
pub(crate) fn bkhash120(x_bytes: &[u8]) -> [u8; HASH_SIZE] {
    // Strip leading zero bytes for minimum-length encoding
    let stripped = match x_bytes.iter().position(|&b| b != 0) {
        Some(pos) => &x_bytes[pos..],
        None => &[0u8], // all zeros -> single zero byte
    };

    let digest = Sha256::digest(stripped);
    let mut result = [0u8; HASH_SIZE];
    result.copy_from_slice(&digest[..HASH_SIZE]);
    result
}

/// Look up a BKHASH120 in the embedded database using binary search.
///
/// Returns `Some(BadKeyInfo)` if found, `None` if not.
pub(crate) fn lookup(hash: &[u8; HASH_SIZE]) -> Option<BadKeyInfo> {
    let num_records = DB.len() / RECORD_SIZE;
    let mut lo: usize = 0;
    let mut hi: usize = num_records;

    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let offset = mid * RECORD_SIZE;
        let record_hash = &DB[offset..offset + HASH_SIZE];

        match hash.as_slice().cmp(record_hash) {
            std::cmp::Ordering::Equal => {
                let category_id = DB[offset + HASH_SIZE];
                return Some(BadKeyInfo {
                    category: Category::from_id(category_id)
                        .unwrap_or(Category::DebianSsl),
                });
            }
            std::cmp::Ordering::Less => hi = mid,
            std::cmp::Ordering::Greater => lo = mid + 1,
        }
    }
    None
}

/// Returns the number of entries in the embedded database.
pub fn entry_count() -> usize {
    DB.len() / RECORD_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bkhash120_no_leading_zeros() {
        // 32 bytes, no leading zeros
        let x = [0xffu8; 32];
        let h = bkhash120(&x);
        assert_eq!(h.len(), HASH_SIZE);
        // Verify it matches SHA-256 of the full 32 bytes
        let expected = Sha256::digest(&x);
        assert_eq!(&h, &expected[..HASH_SIZE]);
    }

    #[test]
    fn test_bkhash120_with_leading_zeros() {
        // Leading zero should be stripped
        let mut x = [0u8; 32];
        x[1] = 0xff; // x = 0x00ff000...
        let h = bkhash120(&x);
        // Should hash only bytes starting from 0xff
        let expected = Sha256::digest(&x[1..]);
        assert_eq!(&h, &expected[..HASH_SIZE]);
    }

    #[test]
    fn test_bkhash120_all_zeros() {
        let x = [0u8; 32];
        let h = bkhash120(&x);
        // Should hash a single 0x00 byte
        let expected = Sha256::digest(&[0u8]);
        assert_eq!(&h, &expected[..HASH_SIZE]);
    }

    #[test]
    fn test_entry_count() {
        // Database should have entries (will fail if DB is empty placeholder)
        let count = entry_count();
        assert!(count > 0, "database should not be empty");
    }

    #[test]
    fn test_lookup_not_found() {
        // Random hash should not be in the database
        let fake_hash = [0xab; HASH_SIZE];
        assert!(lookup(&fake_hash).is_none());
    }
}
