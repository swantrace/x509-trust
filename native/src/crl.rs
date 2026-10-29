use napi::bindgen_prelude::{AsyncTask, Uint8Array};
use napi::{Env, Result, Task};
use napi_derive::napi;
use x509_parser::der_parser::ber::Class;
use x509_parser::oid_registry::{
    OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER, OID_X509_EXT_CRL_NUMBER,
    OID_X509_EXT_DELTA_CRL_INDICATOR, OID_X509_EXT_ISSUER, OID_X509_EXT_ISSUER_DISTRIBUTION_POINT,
};
use x509_parser::prelude::*;

use crate::{invalid, parse_certificate};

#[napi(string_enum = "lowercase")]
pub enum CrlStatus {
    Good,
    Revoked,
    Unknown,
}

#[napi(string_enum = "UPPER_SNAKE")]
pub enum CrlFailureCode {
    #[napi(value = "INVALID_CRL")]
    InvalidCrl,
    #[napi(value = "CRL_ISSUER_MISMATCH")]
    CrlIssuerMismatch,
    #[napi(value = "CRL_ISSUER_NOT_AUTHORIZED")]
    CrlIssuerNotAuthorized,
    #[napi(value = "INVALID_CRL_SIGNATURE")]
    InvalidCrlSignature,
    #[napi(value = "CRL_NOT_YET_VALID")]
    CrlNotYetValid,
    #[napi(value = "CRL_EXPIRED")]
    CrlExpired,
    #[napi(value = "CRL_MISSING_NEXT_UPDATE")]
    CrlMissingNextUpdate,
    #[napi(value = "UNSUPPORTED_CRL")]
    UnsupportedCrl,
}

#[napi(object)]
pub struct NativeCrlResult {
    pub status: CrlStatus,
    pub this_update_ms: Option<f64>,
    pub next_update_ms: Option<f64>,
    pub code: Option<CrlFailureCode>,
    pub message: Option<String>,
}

fn unknown(code: CrlFailureCode, message: &str) -> NativeCrlResult {
    NativeCrlResult {
        status: CrlStatus::Unknown,
        this_update_ms: None,
        next_update_ms: None,
        code: Some(code),
        message: Some(message.to_owned()),
    }
}

fn directory_string(attribute: &AttributeTypeAndValue<'_>) -> Option<String> {
    let value = attribute.attr_value();
    if value.class() != Class::Universal {
        return None;
    }
    match value.tag().0 {
        12 => std::str::from_utf8(value.data).ok().map(str::to_owned),
        30 if value.data.len() % 2 == 0 => {
            let characters: Vec<_> = value
                .data
                .chunks_exact(2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                .collect();
            String::from_utf16(&characters).ok()
        }
        28 if value.data.len() % 4 == 0 => value
            .data
            .chunks_exact(4)
            .map(|bytes| {
                char::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
            })
            .collect(),
        18..=22 | 25..=27 => Some(value.data.iter().map(|byte| char::from(*byte)).collect()),
        _ => None,
    }
}

fn names_equal(left: &X509Name<'_>, right: &X509Name<'_>) -> bool {
    if left.as_raw() == right.as_raw() {
        return true;
    }
    // Preserve case/space-insensitive DirectoryString matching across the
    // string encodings previously handled by PKI.js, without flattening RDNs.
    let normalize = |value: String| {
        value
            .trim()
            .split(' ')
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(" ")
            .to_lowercase()
    };
    left.iter_rdn().count() == right.iter_rdn().count()
        && left.iter_rdn().zip(right.iter_rdn()).all(|(left, right)| {
            left.iter().count() == right.iter().count()
                && left.iter().zip(right.iter()).all(|(left, right)| {
                    left.attr_type() == right.attr_type()
                        && match (directory_string(left), directory_string(right)) {
                            (Some(left), Some(right)) => normalize(left) == normalize(right),
                            _ => left.attr_value() == right.attr_value(),
                        }
                })
        })
}

fn issuer_can_sign_crl(issuer: &X509Certificate<'_>) -> bool {
    if issuer.extensions_map().is_err()
        || !matches!(issuer.basic_constraints(), Ok(Some(constraints)) if constraints.value.ca)
    {
        return false;
    }
    match issuer.key_usage() {
        Ok(None) => true,
        Ok(Some(usage)) => usage.value.crl_sign(),
        Err(_) => false,
    }
}

fn has_unsupported_extensions(crl: &CertificateRevocationList<'_>) -> bool {
    crl.extensions().iter().any(|extension| {
        extension.oid == OID_X509_EXT_DELTA_CRL_INDICATOR
            || extension.oid == OID_X509_EXT_ISSUER_DISTRIBUTION_POINT
            || (extension.critical
                && extension.oid != OID_X509_EXT_AUTHORITY_KEY_IDENTIFIER
                && extension.oid != OID_X509_EXT_CRL_NUMBER)
    }) || crl.iter_revoked_certificates().any(|entry| {
        entry
            .extensions()
            .iter()
            .any(|extension| extension.oid == OID_X509_EXT_ISSUER || extension.critical)
    })
}

pub struct ValidateCrlTask {
    certificate: Vec<u8>,
    issuer: Vec<u8>,
    crl: Vec<u8>,
    check_date_ms: f64,
}

#[napi]
impl Task for ValidateCrlTask {
    type Output = NativeCrlResult;
    type JsValue = NativeCrlResult;

    fn compute(&mut self) -> Result<Self::Output> {
        use CrlFailureCode::*;
        if !self.check_date_ms.is_finite() {
            return Err(invalid("checkDate must be a valid date"));
        }
        let certificate = match parse_certificate(&self.certificate) {
            Ok(certificate) => certificate,
            Err(_) => return Ok(unknown(InvalidCrl, "Unable to parse the DER certificate")),
        };
        let issuer = match parse_certificate(&self.issuer) {
            Ok(issuer) => issuer,
            Err(_) => {
                return Ok(unknown(
                    CrlIssuerNotAuthorized,
                    "Unable to parse the DER issuer certificate",
                ))
            }
        };
        let crl = match parse_x509_crl(&self.crl) {
            Ok(([], crl)) => crl,
            _ => return Ok(unknown(InvalidCrl, "Unable to parse the DER CRL")),
        };
        if !names_equal(certificate.issuer(), issuer.subject())
            || !names_equal(crl.issuer(), issuer.subject())
        {
            return Ok(unknown(
                CrlIssuerMismatch,
                "Certificate and CRL must have the supplied issuer",
            ));
        }
        if !issuer_can_sign_crl(&issuer) {
            return Ok(unknown(
                CrlIssuerNotAuthorized,
                "The issuer must be a CA permitted to sign CRLs",
            ));
        }
        if has_unsupported_extensions(&crl) {
            return Ok(unknown(
                UnsupportedCrl,
                "Only direct, complete CRLs without scope restrictions are supported",
            ));
        }
        if crl.tbs_cert_list.extensions_map().is_err()
            || crl
                .extensions()
                .iter()
                .any(|extension| extension.parsed_extension().error().is_some())
            || crl.iter_revoked_certificates().any(|entry| {
                entry.extensions_map().is_err()
                    || entry
                        .extensions()
                        .iter()
                        .any(|extension| extension.parsed_extension().error().is_some())
            })
        {
            return Ok(unknown(InvalidCrl, "Invalid or duplicate CRL extensions"));
        }
        let this_update_ms = crl.last_update().timestamp() as f64 * 1000.0;
        let Some(next_update) = crl.next_update() else {
            return Ok(unknown(CrlMissingNextUpdate, "CRL nextUpdate is required"));
        };
        let next_update_ms = next_update.timestamp() as f64 * 1000.0;
        if next_update_ms <= this_update_ms {
            return Ok(unknown(InvalidCrl, "Invalid CRL validity interval"));
        }
        if this_update_ms > self.check_date_ms {
            return Ok(unknown(CrlNotYetValid, "CRL thisUpdate is in the future"));
        }
        if next_update_ms <= self.check_date_ms {
            return Ok(unknown(CrlExpired, "CRL nextUpdate has been reached"));
        }
        if crl.tbs_cert_list.signature != crl.signature_algorithm {
            return Ok(unknown(
                InvalidCrlSignature,
                "CRL signature algorithm identifiers do not match",
            ));
        }
        if crl.signature_value.unused_bits != 0 {
            return Ok(unknown(
                InvalidCrlSignature,
                "CRL signature must be byte-aligned",
            ));
        }
        if crl.verify_signature(issuer.public_key()).is_err() {
            return Ok(unknown(
                InvalidCrlSignature,
                "CRL signature is invalid or unsupported",
            ));
        }
        let revoked = crl
            .iter_revoked_certificates()
            .any(|entry| entry.serial() == &certificate.serial);
        Ok(NativeCrlResult {
            status: if revoked {
                CrlStatus::Revoked
            } else {
                CrlStatus::Good
            },
            this_update_ms: Some(this_update_ms),
            next_update_ms: Some(next_update_ms),
            code: None,
            message: None,
        })
    }

    fn resolve(&mut self, _: Env, output: Self::Output) -> Result<Self::JsValue> {
        Ok(output)
    }
}

/// Certificate and issuer must belong to a previously validated path.
#[napi]
pub fn validate_crl(
    certificate: Uint8Array,
    issuer_certificate: Uint8Array,
    crl: Uint8Array,
    check_date_ms: f64,
) -> AsyncTask<ValidateCrlTask> {
    AsyncTask::new(ValidateCrlTask {
        certificate: certificate.to_vec(),
        issuer: issuer_certificate.to_vec(),
        crl: crl.to_vec(),
        check_date_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(tag: u8, value: &[u8]) -> Vec<u8> {
        let length = value.len() as u8;
        let mut der = vec![
            0x30,
            length + 11,
            0x31,
            length + 9,
            0x30,
            length + 7,
            0x06,
            0x03,
            0x55,
            0x04,
            0x03,
            tag,
            length,
        ];
        der.extend_from_slice(value);
        der
    }

    #[test]
    fn matches_directory_strings_across_case_spaces_and_encodings() {
        let utf8 = name(12, b" Example   CA ");
        let printable = name(19, b"example ca");
        let bmp = name(
            30,
            &"EXAMPLE CA"
                .encode_utf16()
                .flat_map(u16::to_be_bytes)
                .collect::<Vec<_>>(),
        );
        let universal = name(
            28,
            &"example ca"
                .chars()
                .flat_map(|value| (value as u32).to_be_bytes())
                .collect::<Vec<_>>(),
        );
        let different = name(12, b"another ca");
        let (_, left) = X509Name::from_der(&utf8).unwrap();
        for input in [&printable, &bmp, &universal] {
            let (_, right) = X509Name::from_der(input).unwrap();
            assert!(names_equal(&left, &right));
        }
        let (_, right) = X509Name::from_der(&different).unwrap();
        assert!(!names_equal(&left, &right));
    }

    #[test]
    fn preserves_rdn_boundaries() {
        let first = name(12, b"example");
        let second = name(12, b"ca");
        let attributes: Vec<_> = first[4..].iter().chain(&second[4..]).copied().collect();
        let mut grouped = vec![
            0x30,
            (attributes.len() + 2) as u8,
            0x31,
            attributes.len() as u8,
        ];
        grouped.extend_from_slice(&attributes);
        let rdns: Vec<_> = first[2..].iter().chain(&second[2..]).copied().collect();
        let mut separate = vec![0x30, rdns.len() as u8];
        separate.extend_from_slice(&rdns);
        let (_, left) = X509Name::from_der(&grouped).unwrap();
        let (_, right) = X509Name::from_der(&separate).unwrap();
        assert!(!names_equal(&left, &right));
    }
}
