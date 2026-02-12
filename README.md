# badkeys-rs

Check P256 (SECP256R1) public keys against an embedded database of 311k+ known-bad keys sourced from the [badkeys project](https://github.com/badkeys/badkeys).

The database is compiled into the binary, so lookups require no I/O and run in O(log n) via binary search. The embedded database is roughly 5 MB, so expect your binary size to grow by that amount.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
badkeys-rs = "0.1"
```

### Check a PEM key

```rust
let pem = std::fs::read("key.pem").unwrap();
match badkeys_rs::check_pem_key(&pem) {
    Ok(Some(info)) => println!("BAD KEY: {}", info.category.description()),
    Ok(None) => println!("key not in database"),
    Err(e) => eprintln!("parse error: {e}"),
}
```

### Check an X.509 certificate

```rust
let cert = std::fs::read("cert.pem").unwrap();
if let Ok(Some(info)) = badkeys_rs::check_certificate(&cert) {
    println!("certificate has a known-bad key ({})", info.category.name());
}
```

### Check a `p256::PublicKey` directly

```rust
use p256::PublicKey;

fn check(key: &PublicKey) {
    if let Some(info) = badkeys_rs::check_pubkey(key) {
        println!("BAD KEY: {}", info.category.name());
    }
}
```

### Other input formats

- `check_der_pubkey(der_data)` -- DER-encoded SubjectPublicKeyInfo
- `check_x_bytes(x_bytes)` -- raw x-coordinate bytes (big-endian)
- `check_pem_key(pem_data)` -- SPKI, PKCS#8, or SEC1 EC PEM
- `database_entry_count()` -- number of entries in the database

## Database sources

The embedded database is generated from several upstream repositories maintained by the badkeys project. Each bad key is tagged with a category indicating why it is compromised:

| Category | Description | Source |
|---|---|---|
| `debianssl` | Debian OpenSSL PRNG bug (CVE-2008-0166) | [badkeys/debianopenssl](https://github.com/badkeys/debianopenssl) |
| `rfc` | Example keys from RFCs/IETF drafts | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `documentation` | Example keys from vendor documentation | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `firmware` | Private keys embedded in firmware | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `localhostcert` | Hardcoded localhost certificate keys | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `softwaretests` | Keys from software test suites | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `testvectors` | Cryptographic test vector keys | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `misc` | Miscellaneous compromised keys | [SecurityFail/kompromat](https://github.com/SecurityFail/kompromat) |
| `gitkeys` | Private keys committed to public git repos | [badkeys/gitkeys](https://github.com/badkeys/gitkeys) |
| `fwkeys` | Private keys extracted from firmware images | [badkeys/fwkeys](https://github.com/badkeys/fwkeys) |
| `pkgkeys` | Private keys found in software packages | [badkeys/pkgkeys](https://github.com/badkeys/pkgkeys) |
| `webkeys` | Private keys exposed on web servers | [badkeys/webkeys](https://github.com/badkeys/webkeys) |

To regenerate the database from upstream sources:

```
make generate
```

This clones the source repositories and builds `data/p256_blocklist.bin`. See `scripts/generate_blocklist.py` for details.

## License

MIT OR Apache-2.0
