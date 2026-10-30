use napi::bindgen_prelude::Uint8Array;
use napi::Result;
use napi_derive::napi;

use crate::{get_uri_subject_alternative_names, parse_certificate};

#[napi(object)]
pub struct LeafCertificateInfo {
    pub uri_subject_alternative_names: Vec<String>,
    pub public_key_spki_der: Uint8Array,
    pub fingerprint256: String,
    pub serial_number: String,
    pub not_before_ms: f64,
    pub not_after_ms: f64,
}

// Worker output owns Rust bytes; JS typed arrays are created only in resolve.
pub(crate) struct LeafCertificate {
    uri_subject_alternative_names: Vec<String>,
    public_key_spki_der: Vec<u8>,
    fingerprint256: String,
    serial_number: String,
    not_before_ms: f64,
    not_after_ms: f64,
}

pub(crate) fn fingerprint256(der: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, der)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl LeafCertificate {
    pub(crate) fn from_der(der: &[u8]) -> Result<Self> {
        let certificate = parse_certificate(der)?;
        Ok(Self {
            uri_subject_alternative_names: get_uri_subject_alternative_names(der)?,
            public_key_spki_der: certificate.public_key().raw.to_vec(),
            fingerprint256: fingerprint256(der),
            // Unsigned, uppercase hex bytes, without INTEGER sign padding.
            serial_number: certificate
                .serial
                .to_bytes_be()
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect(),
            not_before_ms: certificate.validity().not_before.timestamp() as f64 * 1000.0,
            not_after_ms: certificate.validity().not_after.timestamp() as f64 * 1000.0,
        })
    }
}

impl From<LeafCertificate> for LeafCertificateInfo {
    fn from(certificate: LeafCertificate) -> Self {
        Self {
            uri_subject_alternative_names: certificate.uri_subject_alternative_names,
            public_key_spki_der: certificate.public_key_spki_der.into(),
            fingerprint256: certificate.fingerprint256,
            serial_number: certificate.serial_number,
            not_before_ms: certificate.not_before_ms,
            not_after_ms: certificate.not_after_ms,
        }
    }
}
