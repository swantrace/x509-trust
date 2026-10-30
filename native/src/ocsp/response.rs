use der::asn1::{AnyRef, ContextSpecific, ObjectIdentifier};
use der::{Decode, Encode, Reader, SliceReader, TagNumber};
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};
use x509_parser::asn1_rs::BitString;
use x509_parser::prelude::*;

use super::identity::{matches_certificate, responder_is_issuer};
use super::signature::supported_signature_parameters;
use super::{unknown, NativeOcspResult, OcspFailureCode};
use crate::{names::names_equal, parse_certificate, RevocationStatus};

const BASIC_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

// Extract the exact ResponseData TLV, including its original tag and length.
// Re-encoding decoded data could change the message that was actually signed.
fn signed_response_data(basic_der: &[u8]) -> der::Result<(&[u8], u32)> {
    let basic = AnyRef::from_der(basic_der)?;
    let mut reader = SliceReader::new(basic.value())?;
    let data = reader.tlv_bytes()?;
    let response_data = AnyRef::from_der(data)?;
    let mut reader = SliceReader::new(response_data.value())?;
    let version = ContextSpecific::<u32>::decode_explicit(&mut reader, TagNumber::N0)?
        .map_or(0, |version| version.value);
    Ok((data, version))
}

pub(super) fn validate(
    certificate_der: &[u8],
    issuer_der: &[u8],
    response_der: &[u8],
    check_date_ms: f64,
) -> NativeOcspResult {
    use OcspFailureCode::*;
    let certificate = match parse_certificate(certificate_der) {
        Ok(certificate) => certificate,
        Err(_) => return unknown(InvalidOcspResponse, "Unable to parse the DER certificate"),
    };
    let issuer = match parse_certificate(issuer_der) {
        Ok(issuer) => issuer,
        Err(_) => return unknown(OcspIssuerMismatch, "Unable to parse the DER issuer"),
    };
    if !names_equal(certificate.issuer(), issuer.subject()) {
        return unknown(
            OcspIssuerMismatch,
            "Certificate does not have the supplied issuer",
        );
    }
    let outer = match OcspResponse::from_der(response_der) {
        Ok(outer) => outer,
        Err(_) => return unknown(InvalidOcspResponse, "Unable to parse the DER OCSP response"),
    };
    if outer.response_status != OcspResponseStatus::Successful {
        return unknown(
            OcspResponderError,
            "OCSP responder did not return a successful response",
        );
    }
    let Some(bytes) = outer.response_bytes else {
        return unknown(InvalidOcspResponse, "OCSP response has no response bytes");
    };
    if bytes.response_type != BASIC_OCSP {
        return unknown(
            UnsupportedOcspResponse,
            "Only BasicOCSPResponse is supported",
        );
    }
    let (signed_data, version) = match signed_response_data(bytes.response.as_bytes()) {
        Ok(data) => data,
        Err(_) => return unknown(InvalidOcspResponse, "Invalid OCSP response data"),
    };
    if version != 0 {
        return unknown(UnsupportedOcspResponse, "Unsupported OCSP response version");
    }
    let basic = match BasicOcspResponse::from_der(bytes.response.as_bytes()) {
        Ok(basic) => basic,
        Err(_) => return unknown(InvalidOcspResponse, "Unable to parse the BasicOCSPResponse"),
    };
    let mut matches = Vec::new();
    for single in &basic.tbs_response_data.responses {
        match matches_certificate(&single.cert_id, &certificate, &issuer) {
            Some(true) => matches.push(single),
            Some(false) => (),
            None => {
                return unknown(
                    InvalidOcspResponse,
                    "Invalid or unsupported CertID hash algorithm",
                )
            }
        }
    }
    if matches.len() != 1 {
        return unknown(
            OcspCertificateMismatch,
            "OCSP response must contain exactly one matching certificate status",
        );
    }
    let single = matches[0];
    if basic
        .tbs_response_data
        .response_extensions
        .iter()
        .flatten()
        .any(|extension| extension.critical)
        || single
            .single_extensions
            .iter()
            .flatten()
            .any(|extension| extension.critical)
    {
        return unknown(
            UnsupportedOcspResponse,
            "Unsupported critical OCSP extension",
        );
    }
    let Some(next_update) = single.next_update else {
        return unknown(
            OcspMissingNextUpdate,
            "This verifier requires nextUpdate to bound response freshness",
        );
    };
    let produced_at_ms = basic
        .tbs_response_data
        .produced_at
        .0
        .to_unix_duration()
        .as_secs_f64()
        * 1000.0;
    let this_update_ms = single.this_update.0.to_unix_duration().as_secs_f64() * 1000.0;
    let next_update_ms = next_update.0.to_unix_duration().as_secs_f64() * 1000.0;
    if next_update_ms <= this_update_ms {
        return unknown(InvalidOcspResponse, "Invalid OCSP response time interval");
    }
    if produced_at_ms > check_date_ms || this_update_ms > check_date_ms {
        return unknown(
            OcspNotYetValid,
            "OCSP response was produced or updated in the future",
        );
    }
    if next_update_ms <= check_date_ms {
        return unknown(OcspExpired, "OCSP nextUpdate has been reached");
    }
    // Embedded certificates never establish trust. Delegation is not supported.
    if !responder_is_issuer(&basic.tbs_response_data.responder_id, &issuer) {
        return unknown(
            OcspResponderVerificationFailed,
            "Unable to authenticate a direct-issuer OCSP response",
        );
    }
    let Some(signature) = basic.signature.as_bytes() else {
        return unknown(InvalidOcspSignature, "OCSP signature must be byte-aligned");
    };
    if !supported_signature_parameters(&basic.signature_algorithm) {
        return unknown(
            InvalidOcspSignature,
            "Unsupported OCSP signature algorithm parameters",
        );
    }
    let Ok(algorithm_der) = basic.signature_algorithm.to_der() else {
        return unknown(InvalidOcspSignature, "Invalid OCSP signature algorithm");
    };
    let Ok(([], algorithm)) = AlgorithmIdentifier::from_der(&algorithm_der) else {
        return unknown(InvalidOcspSignature, "Invalid OCSP signature algorithm");
    };
    if x509_parser::verify::verify_signature(
        issuer.public_key(),
        &algorithm,
        &BitString::new(0, signature),
        signed_data,
    )
    .is_err()
    {
        return unknown(
            InvalidOcspSignature,
            "OCSP signature is invalid or unsupported",
        );
    }
    let status = match single.cert_status {
        CertStatus::Good(_) => RevocationStatus::Good,
        CertStatus::Revoked(_) => RevocationStatus::Revoked,
        CertStatus::Unknown(_) => {
            return unknown(
                OcspStatusUnknown,
                "OCSP responder reports unknown certificate status",
            )
        }
    };
    NativeOcspResult {
        status,
        this_update_ms: Some(this_update_ms),
        next_update_ms: Some(next_update_ms),
        code: None,
        message: None,
    }
}
