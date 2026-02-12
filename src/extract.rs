use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::PublicKey;

use crate::error::Error;

/// Extract the 32-byte big-endian x-coordinate from a `p256::PublicKey`.
pub(crate) fn x_bytes_from_pubkey(key: &PublicKey) -> [u8; 32] {
    let point = key.to_encoded_point(false);
    let x = point.x().expect("non-identity point");
    let mut result = [0u8; 32];
    result.copy_from_slice(x);
    result
}

/// Try to parse a PEM-encoded public key or private key and extract a P256 public key.
///
/// Tries, in order:
/// 1. SubjectPublicKeyInfo PEM (`-----BEGIN PUBLIC KEY-----`)
/// 2. PKCS#8 private key PEM (`-----BEGIN PRIVATE KEY-----`)
/// 3. SEC1 EC private key PEM (`-----BEGIN EC PRIVATE KEY-----`)
pub(crate) fn pubkey_from_pem(pem_data: &[u8]) -> Result<PublicKey, Error> {
    let pem_str = std::str::from_utf8(pem_data).map_err(|_| Error::PemParse)?;

    // Try SPKI public key PEM
    if let Ok(key) = pem_str.parse::<PublicKey>() {
        return Ok(key);
    }

    // Try PKCS#8 private key PEM -> extract public key
    use p256::pkcs8::DecodePrivateKey;
    if let Ok(secret) = p256::SecretKey::from_pkcs8_pem(pem_str) {
        return Ok(secret.public_key());
    }

    // Try SEC1 EC private key PEM
    #[allow(unused_imports)]
    use sec1::DecodeEcPrivateKey;
    if let Ok(secret) = p256::SecretKey::from_sec1_pem(pem_str) {
        return Ok(secret.public_key());
    }

    Err(Error::PemParse)
}

/// Parse a DER-encoded SubjectPublicKeyInfo and extract a P256 public key.
pub(crate) fn pubkey_from_spki_der(der_data: &[u8]) -> Result<PublicKey, Error> {
    use p256::pkcs8::DecodePublicKey;
    PublicKey::from_public_key_der(der_data).map_err(|_| Error::DerParse)
}

/// Parse a PEM or DER X.509 certificate and extract the P256 public key.
pub(crate) fn pubkey_from_certificate(cert_data: &[u8]) -> Result<PublicKey, Error> {
    use x509_cert::Certificate;

    // Try PEM first
    let cert = if let Ok(pem_str) = std::str::from_utf8(cert_data) {
        use der::DecodePem;
        Certificate::from_pem(pem_str).or_else(|_| {
            use der::Decode;
            Certificate::from_der(cert_data)
        })
    } else {
        use der::Decode;
        Certificate::from_der(cert_data)
    }
    .map_err(|_| Error::CertificateParse)?;

    // Extract the SubjectPublicKeyInfo DER bytes
    let spki = &cert.tbs_certificate.subject_public_key_info;
    let spki_der =
        der::Encode::to_der(spki).map_err(|_| Error::PublicKeyExtraction)?;

    pubkey_from_spki_der(&spki_der)
}
