//! Reads the three relevant files of a CryptoPro container and pulls out
//! the fields we need.
//!
//! Container layout (typical `xxx.000/` folder):
//!
//!   header.key   -- ASN.1: CMS-like wrapper containing
//!                       * algorithm OID  (level 5, UNIVERSAL OID)
//!                       * 8-byte public-key tag       (CONTEXT [10])
//!                       * the X.509 certificate bytes (CONTEXT [5])
//!   primary.key  -- ASN.1 SEQUENCE whose first OCTET STRING is the
//!                   encrypted private key (size_key bytes)
//!   masks.key    -- ASN.1 SEQUENCE whose first two OCTET STRINGs are
//!                       1) the mask (size_key bytes)
//!                       2) the 12-byte salt

use std::fs;
use std::path::{Path, PathBuf};

use crate::asn1::{self, Node, TagClass};
use crate::error::{Error, Result};

/// Which GOST signature/key algorithm the container uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Gost2001,
    Gost2012_256,
    Gost2012_512,
}

impl Algorithm {
    /// Key size in bytes (32 for 256-bit curves, 64 for 512-bit).
    pub fn key_size(self) -> usize {
        match self {
            Algorithm::Gost2012_512 => 64,
            _ => 32,
        }
    }

    fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            "1.2.643.2.2.30.1" => Some(Algorithm::Gost2001),
            "1.2.643.7.1.1.2.2" => Some(Algorithm::Gost2012_256),
            "1.2.643.7.1.1.2.3" => Some(Algorithm::Gost2012_512),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Container {
    pub algorithm: Algorithm,
    /// First 8 bytes of the affine X-coordinate of the public key
    /// (little-endian) — used as a "password correct?" tag.
    pub pub8: [u8; 8],
    /// The X.509 certificate, DER-encoded (ready to wrap in PEM).
    pub cert_der: Vec<u8>,
    /// Encrypted private key bytes (size = `algorithm.key_size()`).
    pub primary_enc: Vec<u8>,
    /// Mask (size = `algorithm.key_size()`).
    pub mask: Vec<u8>,
    /// 12-byte salt used by the KDF.
    pub salt: [u8; 12],
}

fn read_file(dir: &Path, name: &str) -> Result<Vec<u8>> {
    let mut path: PathBuf = dir.to_path_buf();
    path.push(name);
    fs::read(&path).map_err(|e| Error::Io {
        path: path.display().to_string(),
        source: e,
    })
}

/// Try a list of file names in order; return the first one that exists.
/// Used to support newer CryptoPro versions that store the body in
/// `primary2.key` / `masks2.key` instead of (or alongside) the unsuffixed
/// names.
fn read_file_either(dir: &Path, names: &[&str]) -> Result<Vec<u8>> {
    let mut last_err: Option<Error> = None;
    for name in names {
        let path = dir.join(name);
        if path.is_file() {
            return fs::read(&path).map_err(|e| Error::Io {
                path: path.display().to_string(),
                source: e,
            });
        }
        last_err = Some(Error::Io {
            path: path.display().to_string(),
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        });
    }
    Err(last_err
        .unwrap_or_else(|| Error::Container(format!("none of {names:?} exist in container"))))
}

pub fn load(dir: &Path) -> Result<Container> {
    load_with_certificate(dir, None)
}

pub(super) fn load_with_certificate(dir: &Path, certificate: Option<&[u8]>) -> Result<Container> {
    let header_bytes = read_file(dir, "header.key")?;
    let primary_bytes = read_file_either(dir, &["primary.key", "primary2.key"])?;
    let masks_bytes = read_file_either(dir, &["masks.key", "masks2.key"])?;
    from_bytes_with_certificate(&header_bytes, &primary_bytes, &masks_bytes, certificate)
}

/// Load a container directly from in-memory byte buffers — no filesystem
/// access.  Used by the WASM wrapper.
pub fn from_bytes(
    header_bytes: &[u8],
    primary_bytes: &[u8],
    masks_bytes: &[u8],
) -> Result<Container> {
    from_bytes_with_certificate(header_bytes, primary_bytes, masks_bytes, None)
}

fn from_bytes_with_certificate(
    header_bytes: &[u8],
    primary_bytes: &[u8],
    masks_bytes: &[u8],
    certificate: Option<&[u8]>,
) -> Result<Container> {
    let header =
        asn1::parse(header_bytes).map_err(|e| Error::Container(format!("header.key: {e}")))?;
    let primary =
        asn1::parse(primary_bytes).map_err(|e| Error::Container(format!("primary.key: {e}")))?;
    let masks =
        asn1::parse(masks_bytes).map_err(|e| Error::Container(format!("masks.key: {e}")))?;

    let (algorithm, pub8, cert_der) = parse_header(&header, certificate)?;
    let primary_enc =
        first_octet_string(&primary).ok_or(Error::MissingField("primary.key: encrypted key"))?;
    let (mask, salt_vec) = parse_masks(&masks)?;

    if primary_enc.len() < algorithm.key_size() {
        return Err(Error::Container(format!(
            "primary.key too short: {} < {}",
            primary_enc.len(),
            algorithm.key_size()
        )));
    }
    if mask.len() < algorithm.key_size() {
        return Err(Error::Container(format!(
            "masks.key mask too short: {} < {}",
            mask.len(),
            algorithm.key_size()
        )));
    }
    if salt_vec.len() != 12 {
        return Err(Error::Container(format!(
            "masks.key salt has unexpected length {}",
            salt_vec.len()
        )));
    }
    let mut salt = [0u8; 12];
    salt.copy_from_slice(&salt_vec);

    Ok(Container {
        algorithm,
        pub8,
        cert_der,
        primary_enc: primary_enc[..algorithm.key_size()].to_vec(),
        mask: mask[..algorithm.key_size()].to_vec(),
        salt,
    })
}

/// Find algorithm OID + pub8 + cert blob inside header.key.
fn parse_header(root: &Node, certificate: Option<&[u8]>) -> Result<(Algorithm, [u8; 8], Vec<u8>)> {
    // Algorithm: any OID anywhere in the tree that matches one of the three we know.
    let mut all_oids = Vec::new();
    root.collect_oids(&mut all_oids);
    let mut algorithm: Option<Algorithm> = None;
    for o in &all_oids {
        let s = o.as_oid_string()?;
        if let Some(alg) = Algorithm::from_oid(&s) {
            algorithm = Some(alg);
            break;
        }
    }
    let algorithm = algorithm.ok_or(Error::AlgorithmMissing)?;

    // pub8 and cert are context-specific tags [10] and [5] respectively.
    let mut ctx = Vec::new();
    root.collect_context(&[], &mut ctx);
    let mut pub8: Option<[u8; 8]> = None;
    let mut cert = certificate.map(<[u8]>::to_vec);
    for (_path, node) in ctx {
        if node.class == TagClass::ContextSpecific {
            if node.tag == 10 && pub8.is_none() && node.content.len() >= 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&node.content[..8]);
                pub8 = Some(b);
            }
            if node.tag == 5 && cert.is_none() {
                cert = Some(node.content.clone());
            }
        }
    }
    let pub8 = pub8.ok_or(Error::MissingField("header.key: [10] pub8"))?;
    let cert = cert.ok_or(Error::MissingField("header.key: [5] certificate"))?;
    Ok((algorithm, pub8, cert))
}

fn first_octet_string(root: &Node) -> Option<Vec<u8>> {
    walk_octet_strings(root).into_iter().next()
}

fn parse_masks(root: &Node) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut strings = walk_octet_strings(root);
    if strings.len() < 2 {
        return Err(Error::Container(
            "masks.key: fewer than two OCTET STRINGs".into(),
        ));
    }
    let salt = strings.remove(1);
    let mask = strings.remove(0);
    Ok((mask, salt))
}

/// Collect OCTET STRING contents in document order, *only direct children*
/// of the root — this matches the original handler's `index` semantics.
fn walk_octet_strings(root: &Node) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for c in &root.children {
        if c.is_octet_string() {
            out.push(c.content.clone());
        }
    }
    out
}
