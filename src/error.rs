use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("ASN.1 parse error: {0}")]
    Asn1(String),

    #[error("Container structure error: {0}")]
    Container(String),

    #[error("Unsupported algorithm OID: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Algorithm not detected in header.key")]
    AlgorithmMissing,

    #[error("Missing field in container: {0}")]
    MissingField(&'static str),

    #[error("Invalid external certificate: {0}")]
    Certificate(String),

    #[error("External certificate does not match the container's private key")]
    CertificateMismatch,

    #[error("Invalid password (public key check failed)")]
    InvalidPassword,

    #[error("Cryptographic operation failed: {0}")]
    Crypto(&'static str),

    #[error("PFX/PKCS#12 error: {0}")]
    Pfx(String),

    #[error("Unsupported PBE / encryption scheme: {0}")]
    UnsupportedPbe(String),

    #[error("PFX MAC verification failed (wrong password or tampered file)")]
    MacFailed,
}

pub type Result<T> = std::result::Result<T, Error>;
