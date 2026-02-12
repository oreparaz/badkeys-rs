use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to parse PEM data")]
    PemParse,

    #[error("failed to parse DER data")]
    DerParse,

    #[error("not a P256 key")]
    NotP256,

    #[error("failed to parse X.509 certificate")]
    CertificateParse,

    #[error("failed to extract public key")]
    PublicKeyExtraction,
}
