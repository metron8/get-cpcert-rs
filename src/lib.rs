//! `get-cpcert-rs` — extract certificate + private key from a CryptoPro 4/5
//! container (PEM output, compatible with GOST-enabled OpenSSL 1.1.1+).
//!
//! See `extract` for the high-level API.

use std::path::Path;

use num_bigint_dig::{BigUint, ModInverse};
use num_traits::ToPrimitive;
use zeroize::{Zeroize, Zeroizing};

pub mod asn1;
mod certificate;
pub mod container;
pub mod error;
pub mod gost28147;
pub mod gost_ec;
pub mod kdf;
pub mod oid;
pub mod pem_out;
pub mod pfx;

pub use crate::pfx::extract_from_pfx;

use crate::container::{Algorithm, Container};
use crate::error::{Error, Result};
use crate::gost28147::{Gost28147, SBox};
use crate::gost_ec::{Curve, Point};

/// End-to-end: read the container from `dir`, decrypt with `password`,
/// verify against the stored public key tag, and return the PEM bundle
/// (certificate + PKCS#8 private key).
pub fn extract(dir: &Path, password: &str) -> Result<String> {
    let container = container::load(dir)?;
    extract_from_container(&container, password)
}

pub fn extract_from_container(container: &Container, password: &str) -> Result<String> {
    extract_checked(container, password, None)
}

/// Extract a PEM bundle using one external X.509 certificate (DER or PEM).
/// The certificate must match the recovered key and a supported GOST curve.
/// This does not validate the certificate's trust chain or validity period.
pub fn extract_with_certificate(dir: &Path, password: &str, certificate: &[u8]) -> Result<String> {
    let certificate = certificate::Certificate::parse(certificate)?;
    let container = container::load_with_certificate(dir, Some(certificate.der()))?;
    extract_checked(&container, password, Some(&certificate))
}

fn extract_checked(
    container: &Container,
    password: &str,
    certificate: Option<&certificate::Certificate>,
) -> Result<String> {
    // 1. Derive the symmetric key from the password.
    let mut pwd_key = Zeroizing::new(match container.algorithm {
        Algorithm::Gost2001 => kdf::derive_2001(&container.salt, password),
        Algorithm::Gost2012_256 | Algorithm::Gost2012_512 => {
            kdf::derive_2012(&container.salt, password)
        }
    });

    // 2. Choose 28147-89 S-box per algorithm.
    let sbox = match container.algorithm {
        Algorithm::Gost2001 => SBox::CRYPTOPRO_A,
        Algorithm::Gost2012_256 | Algorithm::Gost2012_512 => SBox::TC26_Z,
    };

    // 3. Decrypt the wrapped key. ECB, blocks of 8 bytes.
    let mut buf = container.primary_enc.clone();
    {
        let cipher = Gost28147::new(&pwd_key, sbox);
        cipher.decrypt_ecb(&mut buf);
    }

    // Reverse to big-endian (the C code does BUF_reverse here).
    buf.reverse();
    let key_with_mask = BigUint::from_bytes_be(&buf);

    // 4. Pick the right curve & order.
    let curve = match container.algorithm {
        Algorithm::Gost2001 | Algorithm::Gost2012_256 => Curve::cryptopro_xch_a(),
        Algorithm::Gost2012_512 => Curve::tc26_512_a(),
    };

    // 5. Reverse the mask too, then compute raw_secret = key_with_mask * mask^-1 mod q.
    let mut mask_be = container.mask.clone();
    mask_be.reverse();
    let mask = BigUint::from_bytes_be(&mask_be);
    let mask_inv = mask
        .mod_inverse(&curve.q)
        .ok_or(Error::Crypto("mask not invertible"))?
        .to_biguint()
        .ok_or(Error::Crypto("mask inverse negative"))?;
    let raw_secret = (&key_with_mask * &mask_inv) % &curve.q;

    // 6. Compute Q = d·G and check first 8 bytes of X against pub8.
    let q_point = Point::base(&curve).scalar_mul(&raw_secret, &curve);
    let q_x = match &q_point {
        Point::Affine { x, .. } => x,
        Point::Infinity => return Err(Error::InvalidPassword),
    };
    let x_be = gost_ec::to_be_bytes_padded(q_x, curve.coord_bytes);
    let mut x_le: Vec<u8> = x_be.into_iter().rev().collect();
    let matches = x_le[..8] == container.pub8;
    x_le.zeroize();
    if !matches {
        // Wipe and bail.
        pwd_key.zeroize();
        return Err(Error::InvalidPassword);
    }

    if let Some(certificate) = certificate {
        certificate.verify_key(container.algorithm, &q_point)?;
    }

    // 7. Format the private key bytes as the templates expect:
    //    little-endian, padded to `key_size`.
    let mut raw_priv_be = gost_ec::to_be_bytes_padded(&raw_secret, curve.coord_bytes);
    raw_priv_be.reverse();
    let raw_priv_le = raw_priv_be;
    // (Length sanity)
    let _ = (raw_priv_le.len()).to_u32(); // silence unused warning

    // 8. Build PKCS#8 + cert PEM.
    let pkcs8 = pem_out::build_private_key_der(container.algorithm, &raw_priv_le);
    let pem = pem_out::build_pem(&container.cert_der, &pkcs8);

    // Hygiene
    pwd_key.zeroize();
    let mut raw_priv_le = raw_priv_le;
    raw_priv_le.zeroize();

    Ok(pem)
}
