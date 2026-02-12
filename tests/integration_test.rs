use badkeys_rs::{BadKeyInfo, Category};

/// A known-bad Debian OpenSSL P256 key (from debianopenssl/ecp256/ssl/be32/0-rnd.key).
const BAD_KEY_PEM: &[u8] = b"-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINjMoC7XdVW5KzVPk5po8p7K1yIa4RyZXKkExJlLfWa9oAoGCCqGSM49
AwEHoUQDQgAEIIKKcNa9RslfoyaWr8XvoeCptYjUnp49gRCpY8QhDzWVTVnqZoZZ
JiHnRJDLqop+YZV2GjvCay1ejGLYXVAK0w==
-----END EC PRIVATE KEY-----
";

/// The x-coordinate of the bad key above (hex).
const BAD_KEY_X_HEX: &str =
    "20828a70d6bd46c95fa32696afc5efa1e0a9b588d49e9e3d8110a963c4210f35";

#[test]
fn check_known_bad_pem_key() {
    let result = badkeys_rs::check_pem_key(BAD_KEY_PEM).expect("should parse PEM");
    assert!(result.is_some(), "known-bad key should be detected");
    let info = result.unwrap();
    assert_eq!(info.category, Category::DebianSsl);
}

#[test]
fn check_known_bad_x_bytes() {
    let x_bytes = hex_to_bytes(BAD_KEY_X_HEX);
    let result = badkeys_rs::check_x_bytes(&x_bytes);
    assert!(result.is_some(), "known-bad x-coordinate should be detected");
    assert_eq!(result.unwrap().category, Category::DebianSsl);
}

#[test]
fn check_known_good_key_returns_none() {
    // A freshly generated P256 key that is NOT in the blocklist.
    let good_pem = b"-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuZTacA5IcYdINDy+qAsSabZu6JSg
E2nuNwLKmvfSbZq1goVdqGKoeWf//vSRUGIzmW4JbdsiXY14WXDx9a6bmg==
-----END PUBLIC KEY-----
";
    let result = badkeys_rs::check_pem_key(good_pem).expect("should parse PEM");
    assert!(result.is_none(), "fresh key should not be in blocklist");
}

#[test]
fn check_all_zeros_x_not_in_database() {
    // x=0 is not a valid P256 point, so it should not be in the blocklist.
    let zero_x = [0u8; 32];
    let result = badkeys_rs::check_x_bytes(&zero_x);
    assert!(result.is_none(), "all-zeros x-coordinate should not be in blocklist");
}

#[test]
fn check_random_x_bytes_returns_none() {
    let random_x = [0x42u8; 32];
    let result = badkeys_rs::check_x_bytes(&random_x);
    assert!(result.is_none(), "random x-coordinate should not match");
}

#[test]
fn database_has_entries() {
    let count = badkeys_rs::database_entry_count();
    assert!(count > 300_000, "expected >300k entries, got {count}");
}

#[test]
fn bad_key_info_debug() {
    let info = BadKeyInfo {
        category: Category::DebianSsl,
    };
    let debug = format!("{:?}", info);
    assert!(debug.contains("DebianSsl"));
}

#[test]
fn invalid_pem_returns_error() {
    let result = badkeys_rs::check_pem_key(b"not a pem");
    assert!(result.is_err());
}

#[test]
fn invalid_der_returns_error() {
    let result = badkeys_rs::check_der_pubkey(b"\x00\x01\x02");
    assert!(result.is_err());
}

#[test]
fn invalid_certificate_returns_error() {
    let result = badkeys_rs::check_certificate(b"not a cert");
    assert!(result.is_err());
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect()
}
