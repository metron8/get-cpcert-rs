//! External certificates are parsed separately from CryptoPro's container ASN.1.

use x509_cert::der::{asn1::ObjectIdentifier, asn1::OctetStringRef, Decode};

use crate::container::Algorithm;
use crate::error::{Error, Result};
use crate::gost_ec::{to_be_bytes_padded, Point};

const GOST_2001: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.19");
const GOST_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.1.1");
const GOST_512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.1.1.2");
const CRYPTOPRO_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.35.1");
const CRYPTOPRO_XCHA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.2.2.36.0");
const TC26_256_B: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.2.1.1.2");
const TC26_512_A: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.643.7.1.2.1.2.1");

pub struct Certificate {
    der: Vec<u8>,
    algorithm: Algorithm,
    public_key: Vec<u8>,
}

impl Certificate {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let der = decode_certificate(bytes)?;
        let parsed = x509_cert::Certificate::from_der(&der)
            .map_err(|e| Error::Certificate(e.to_string()))?;
        let spki = parsed.tbs_certificate.subject_public_key_info;
        let algorithm = match spki.algorithm.oid {
            GOST_2001 => Algorithm::Gost2001,
            GOST_256 => Algorithm::Gost2012_256,
            GOST_512 => Algorithm::Gost2012_512,
            oid => return Err(Error::UnsupportedAlgorithm(oid.to_string())),
        };
        let parameters = spki
            .algorithm
            .parameters
            .ok_or_else(|| Error::Certificate("missing GOST curve parameters".into()))?;
        let parameters = parameters
            .decode_as::<Vec<ObjectIdentifier>>()
            .map_err(|e| Error::Certificate(e.to_string()))?;
        validate_curve(algorithm, &parameters)?;
        let bits = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| Error::Certificate("public key is not byte-aligned".into()))?;
        let public_key =
            OctetStringRef::from_der(bits).map_err(|e| Error::Certificate(e.to_string()))?;
        if public_key.as_bytes().len() != 2 * algorithm.key_size() {
            return Err(Error::Certificate(
                "unexpected GOST public key length".into(),
            ));
        }
        Ok(Self {
            der,
            algorithm,
            public_key: public_key.as_bytes().to_vec(),
        })
    }

    pub fn der(&self) -> &[u8] {
        &self.der
    }

    pub fn verify_key(&self, algorithm: Algorithm, point: &Point) -> Result<()> {
        if self.algorithm != algorithm {
            return Err(Error::CertificateMismatch);
        }
        let (x, y) = match point {
            Point::Affine { x, y } => (x, y),
            Point::Infinity => return Err(Error::CertificateMismatch),
        };
        let mut encoded = to_be_bytes_padded(x, algorithm.key_size());
        encoded.reverse();
        let mut y = to_be_bytes_padded(y, algorithm.key_size());
        y.reverse();
        encoded.extend_from_slice(&y);
        if encoded != self.public_key {
            return Err(Error::CertificateMismatch);
        }
        Ok(())
    }
}

fn decode_certificate(bytes: &[u8]) -> Result<Vec<u8>> {
    if bytes.first() == Some(&0x30) {
        return Ok(bytes.to_vec());
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|e| Error::Certificate(e.to_string()))?
        .trim();
    if !text.starts_with("-----BEGIN CERTIFICATE-----")
        || !text.ends_with("-----END CERTIFICATE-----")
    {
        return Err(Error::Certificate(
            "expected one DER or PEM X.509 certificate".into(),
        ));
    }
    let mut blocks = pem::parse_many(text).map_err(|e| Error::Certificate(e.to_string()))?;
    if blocks.len() != 1 {
        return Err(Error::Certificate(
            "expected exactly one PEM certificate".into(),
        ));
    }
    let block = blocks
        .pop()
        .ok_or_else(|| Error::Certificate("missing PEM certificate".into()))?;
    if block.tag() != "CERTIFICATE" {
        return Err(Error::Certificate("expected CERTIFICATE PEM label".into()));
    }
    Ok(block.into_contents())
}

fn validate_curve(algorithm: Algorithm, parameters: &[ObjectIdentifier]) -> Result<()> {
    let curve = match parameters {
        [curve] | [curve, _] | [curve, _, _] => *curve,
        _ => {
            return Err(Error::Certificate(
                "invalid GOST algorithm parameters".into(),
            ))
        }
    };
    // CryptoPro A, XchA and TC26 256-B use the same curve and base point.
    let supported = match algorithm {
        Algorithm::Gost2001 => curve == CRYPTOPRO_A || curve == CRYPTOPRO_XCHA,
        Algorithm::Gost2012_256 => {
            curve == CRYPTOPRO_A || curve == CRYPTOPRO_XCHA || curve == TC26_256_B
        }
        Algorithm::Gost2012_512 => curve == TC26_512_A,
    };
    if !supported {
        return Err(Error::Certificate(format!(
            "unsupported GOST curve: {curve}"
        )));
    }
    Ok(())
}
